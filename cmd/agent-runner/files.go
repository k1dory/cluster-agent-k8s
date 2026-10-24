package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"agent-sandbox/internal/model"
)

// Limits of the workspace file operations.
const (
	maxFileBytes   = 16 << 20
	maxListEntries = 5000
)

func workspaceRoot() string {
	if r := os.Getenv("SANDBOX_WORKSPACE"); r != "" {
		return r
	}
	return "/workspace"
}

// serveFiles long-polls for file operations the control plane asked for and answers them:
// listings and reads of the workspace, writes of uploaded content. It runs beside the run
// loop, so files are reachable while the agent works and while it waits.
func serveFiles(ctx context.Context, c *client, root string) {
	var after int64
	for ctx.Err() == nil {
		var evs []model.Event
		_, err := c.do(ctx, http.MethodGet, fmt.Sprintf("/agent/fs/requests?after=%d&wait=30s", after), nil, &evs)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			time.Sleep(5 * time.Second)
			continue
		}
		for _, e := range evs {
			after = e.ID
			var req model.FSRequest
			if json.Unmarshal([]byte(e.Data), &req) != nil {
				continue
			}
			res := c.serveFile(ctx, root, req)
			body, _ := json.Marshal(res)
			if _, err := c.do(ctx, http.MethodPost, "/agent/fs/results", body, nil); err != nil {
				fmt.Fprintln(os.Stderr, "agent-runner: file result:", err)
			}
		}
	}
}

func (c *client) serveFile(ctx context.Context, root string, req model.FSRequest) model.FSResult {
	res := model.FSResult{Request: req.ID}
	full, err := resolve(root, req.Path)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	switch req.Op {
	case model.FSList:
		entries, truncated, err := listDir(root, full, req.Depth)
		if err != nil {
			res.Error = err.Error()
			return res
		}
		res.OK, res.Entries, res.Truncated = true, entries, truncated
	case model.FSRead:
		data, ct, err := readFile(full)
		if err != nil {
			res.Error = err.Error()
			return res
		}
		var out struct {
			Name string `json:"name"`
		}
		if _, err := c.do(ctx, http.MethodPost, "/agent/blobs", data, &out); err != nil {
			res.Error = "upload: " + err.Error()
			return res
		}
		res.OK, res.Blob, res.Size, res.ContentType = true, out.Name, int64(len(data)), ct
	case model.FSWrite:
		data, err := c.fetchBlob(ctx, req.Blob)
		if err != nil {
			res.Error = "download: " + err.Error()
			return res
		}
		if err := writeFile(full, data); err != nil {
			res.Error = err.Error()
			return res
		}
		res.OK, res.Size = true, int64(len(data))
	default:
		res.Error = "unknown operation " + req.Op
	}
	return res
}

// resolve confines a request path to the workspace root (no escape through .. or symlinks
// that leave the root).
func resolve(root, p string) (string, error) {
	clean := filepath.Clean("/" + filepath.FromSlash(p))
	full := filepath.Join(root, clean)
	if full != root && !strings.HasPrefix(full, root+string(filepath.Separator)) {
		return "", errors.New("path escapes the workspace")
	}
	if real, err := filepath.EvalSymlinks(full); err == nil {
		rootReal, _ := filepath.EvalSymlinks(root)
		if rootReal == "" {
			rootReal = root
		}
		if real != rootReal && !strings.HasPrefix(real, rootReal+string(filepath.Separator)) {
			return "", errors.New("path escapes the workspace")
		}
	}
	return full, nil
}

func listDir(root, full string, depth int) ([]model.FSEntry, bool, error) {
	if depth < 1 {
		depth = 1
	}
	st, err := os.Stat(full)
	if err != nil {
		return nil, false, err
	}
	if !st.IsDir() {
		return nil, false, errors.New(full + ": not a directory")
	}
	var out []model.FSEntry
	truncated := false
	var walk func(dir string, level int) error
	walk = func(dir string, level int) error {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		for _, de := range entries {
			if len(out) >= maxListEntries {
				truncated = true
				return nil
			}
			p := filepath.Join(dir, de.Name())
			rel, _ := filepath.Rel(root, p)
			e := model.FSEntry{Path: filepath.ToSlash(rel)}
			info, err := de.Info()
			if err == nil {
				e.ModTime = info.ModTime().UTC()
			}
			switch {
			case de.Type()&fs.ModeSymlink != 0:
				e.Type = "symlink"
			case de.IsDir():
				e.Type = "dir"
			case de.Type().IsRegular():
				e.Type = "file"
				if info != nil {
					e.Size = info.Size()
				}
			default:
				e.Type = "other"
			}
			out = append(out, e)
			if e.Type == "dir" && level < depth {
				if err := walk(p, level+1); err != nil && !errors.Is(err, fs.ErrPermission) {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(full, 1); err != nil {
		return nil, false, err
	}
	return out, truncated, nil
}

func readFile(full string) ([]byte, string, error) {
	st, err := os.Stat(full)
	if err != nil {
		return nil, "", err
	}
	if st.IsDir() {
		return nil, "", errors.New(full + ": is a directory")
	}
	if st.Size() > maxFileBytes {
		return nil, "", fmt.Errorf("%s: too large (%d bytes, limit %d)", full, st.Size(), maxFileBytes)
	}
	data, err := os.ReadFile(full)
	if err != nil {
		return nil, "", err
	}
	return data, http.DetectContentType(data), nil
}

func writeFile(full string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return err
	}
	tmp := full + ".agent-runner.tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, full)
}

func (c *client) fetchBlob(ctx context.Context, name string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/agent/blobs/"+name, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("%s: %s", resp.Status, bytes.TrimSpace(b))
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxFileBytes+1))
}
