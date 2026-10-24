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
	"path"
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
// loop, so files are reachable while the agent works and while it waits. The cursor moves
// past a request only once its answer is acknowledged: an answer lost to a transient failure
// is retried, and a request still unanswered is delivered again by the next poll.
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
			var req model.FSRequest
			if json.Unmarshal([]byte(e.Data), &req) != nil {
				after = e.ID
				continue
			}
			res := c.serveFile(ctx, root, req)
			if err := c.postResult(ctx, res); err != nil {
				fmt.Fprintln(os.Stderr, "agent-runner: file result not acknowledged, will retry:", err)
				break // the cursor stays: the next poll delivers this request again
			}
			after = e.ID
		}
	}
}

// postResult delivers an answer and insists on an acknowledgement: transient failures (5xx,
// network) are retried with backoff; a 4xx means the answer is not wanted.
func (c *client) postResult(ctx context.Context, res model.FSResult) error {
	body, _ := json.Marshal(res)
	var lastErr error
	for attempt := 0; attempt < 5 && ctx.Err() == nil; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(1<<attempt) * 250 * time.Millisecond):
			}
		}
		code, err := c.do(ctx, http.MethodPost, "/agent/fs/results", body, nil)
		if err == nil {
			return nil
		}
		if code >= 400 && code < 500 {
			return nil // refused for good: nothing to retry
		}
		lastErr = err
	}
	return lastErr
}

// serveFile performs one request inside the workspace. Every path is opened relative to the
// workspace root with os.Root, so neither ".." nor a symlink (of the file or any parent,
// existing or about to be created) can reach outside it.
func (c *client) serveFile(ctx context.Context, root string, req model.FSRequest) model.FSResult {
	res := model.FSResult{Request: req.ID}
	ws, err := os.OpenRoot(root)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer ws.Close()
	rel, err := relPath(req.Path)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	switch req.Op {
	case model.FSList:
		entries, truncated, err := listDir(ws, rel, req.Depth)
		if err != nil {
			res.Error = fsError(err)
			return res
		}
		res.OK, res.Entries, res.Truncated = true, entries, truncated
	case model.FSRead:
		data, ct, err := readFile(ws, rel)
		if err != nil {
			res.Error = fsError(err)
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
		if err := writeFile(ws, rel, data); err != nil {
			res.Error = fsError(err)
			return res
		}
		res.OK, res.Size = true, int64(len(data))
	default:
		res.Error = "unknown operation " + req.Op
	}
	return res
}

// relPath normalises a request path to a clean relative one ("." for the root). Escapes are
// refused here as well, though os.Root would refuse them too.
func relPath(p string) (string, error) {
	p = strings.TrimPrefix(strings.TrimSpace(p), "/workspace")
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return "", errors.New(p + ": path escapes the workspace")
		}
	}
	clean := path.Clean("/" + p)
	if clean == "/" {
		return ".", nil
	}
	return strings.TrimPrefix(clean, "/"), nil
}

// fsError turns os.Root's refusals and OS errors into the messages the API maps to statuses.
func fsError(err error) string {
	var pe *os.PathError
	if errors.As(err, &pe) && strings.Contains(pe.Err.Error(), "escapes from parent") {
		return pe.Path + ": path escapes the workspace"
	}
	return err.Error()
}

func listDir(ws *os.Root, rel string, depth int) ([]model.FSEntry, bool, error) {
	if depth < 1 {
		depth = 1
	}
	st, err := ws.Stat(rel)
	if err != nil {
		return nil, false, err
	}
	if !st.IsDir() {
		return nil, false, errors.New(rel + ": not a directory")
	}
	var out []model.FSEntry
	truncated := false
	var walk func(dir string, level int) error
	walk = func(dir string, level int) error {
		f, err := ws.Open(dir)
		if err != nil {
			return err
		}
		entries, err := f.ReadDir(-1)
		f.Close()
		if err != nil {
			return err
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		for _, de := range entries {
			if len(out) >= maxListEntries {
				truncated = true
				return nil
			}
			p := de.Name()
			if dir != "." {
				p = dir + "/" + de.Name()
			}
			e := model.FSEntry{Path: p}
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
	if err := walk(rel, 1); err != nil {
		return nil, false, err
	}
	return out, truncated, nil
}

func readFile(ws *os.Root, rel string) ([]byte, string, error) {
	st, err := ws.Stat(rel)
	if err != nil {
		return nil, "", err
	}
	if st.IsDir() {
		return nil, "", errors.New(rel + ": is a directory")
	}
	if st.Size() > maxFileBytes {
		return nil, "", fmt.Errorf("%s: too large (%d bytes, limit %d)", rel, st.Size(), maxFileBytes)
	}
	data, err := ws.ReadFile(rel)
	if err != nil {
		return nil, "", err
	}
	return data, http.DetectContentType(data), nil
}

// writeFile writes atomically (temporary file, then rename) inside the workspace root;
// parents are created inside it too.
func writeFile(ws *os.Root, rel string, data []byte) error {
	if rel == "." {
		return errors.New("path is required")
	}
	if dir := path.Dir(rel); dir != "." {
		if err := ws.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	tmp := rel + ".agent-runner.tmp"
	if err := ws.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	if err := ws.Rename(tmp, rel); err != nil {
		_ = ws.Remove(tmp)
		return err
	}
	return nil
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
