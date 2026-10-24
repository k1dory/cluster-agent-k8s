package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"agent-sandbox/internal/model"
)

func TestServeFileOperations(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "repo", "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(root, "repo", "src", "main.go"), []byte("package main\n"), 0o644)
	_ = os.WriteFile(filepath.Join(root, "repo", "README.md"), []byte("# hi\n"), 0o644)
	outside := t.TempDir()
	_ = os.WriteFile(filepath.Join(outside, "secret"), []byte("s"), 0o644)
	_ = os.Symlink(outside, filepath.Join(root, "escape"))
	blobs := map[string][]byte{"fs/sb/in": []byte("uploaded content")}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/agent/blobs":
			b, _ := readAll(r)
			blobs["fs/sb/out"] = b
			_ = json.NewEncoder(w).Encode(map[string]any{"name": "fs/sb/out"})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/agent/blobs/"):
			b, ok := blobs[strings.TrimPrefix(r.URL.Path, "/agent/blobs/")]
			if !ok {
				http.Error(w, "no such blob", http.StatusNotFound)
				return
			}
			w.Write(b)
		default:
			http.Error(w, "unexpected "+r.URL.Path, http.StatusNotFound)
		}
	}))
	defer server.Close()
	c := &client{base: server.URL, http: server.Client()}
	ctx := context.Background()
	// list, one level and deep
	res := c.serveFile(ctx, root, model.FSRequest{ID: "1", Op: model.FSList, Path: "repo"})
	if !res.OK || len(res.Entries) != 2 || res.Entries[0].Path != "repo/README.md" || res.Entries[1].Type != "dir" {
		t.Fatalf("list: %+v", res)
	}
	res = c.serveFile(ctx, root, model.FSRequest{ID: "2", Op: model.FSList, Path: "", Depth: 3})
	var paths []string
	for _, e := range res.Entries {
		paths = append(paths, e.Type+":"+e.Path)
	}
	if !res.OK || strings.Join(paths, ",") != "symlink:escape,dir:repo,file:repo/README.md,dir:repo/src,file:repo/src/main.go" {
		t.Fatalf("deep list: %v", paths)
	}
	// read uploads a blob; the content type is detected
	res = c.serveFile(ctx, root, model.FSRequest{ID: "3", Op: model.FSRead, Path: "repo/src/main.go"})
	if !res.OK || res.Blob != "fs/sb/out" || res.Size != 13 || string(blobs["fs/sb/out"]) != "package main\n" || !strings.HasPrefix(res.ContentType, "text/plain") {
		t.Fatalf("read: %+v", res)
	}
	// write fetches the blob and creates parents
	res = c.serveFile(ctx, root, model.FSRequest{ID: "4", Op: model.FSWrite, Path: "uploads/spec/notes.txt", Blob: "fs/sb/in"})
	if b, err := os.ReadFile(filepath.Join(root, "uploads", "spec", "notes.txt")); !res.OK || err != nil || string(b) != "uploaded content" {
		t.Fatalf("write: %+v %v", res, err)
	}
	// errors: escape attempts (.. and a symlink out of the root), missing files, directories, unknown ops
	for _, bad := range []model.FSRequest{
		{Op: model.FSRead, Path: "../" + filepath.Base(outside) + "/secret"},
		{Op: model.FSRead, Path: "escape/secret"},
		{Op: model.FSList, Path: "escape"},
		{Op: model.FSRead, Path: "repo/missing.go"},
		{Op: model.FSRead, Path: "repo"},
		{Op: model.FSList, Path: "repo/README.md"},
		{Op: "rm", Path: "repo"},
		{Op: model.FSWrite, Path: "x", Blob: "fs/sb/missing"},
	} {
		if res := c.serveFile(ctx, root, bad); res.OK {
			t.Errorf("%+v must fail", bad)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "x")); err == nil {
		t.Fatal("a failed write must not leave a file")
	}
}

func readAll(r *http.Request) ([]byte, error) {
	defer r.Body.Close()
	var buf strings.Builder
	b := make([]byte, 4096)
	for {
		n, err := r.Body.Read(b)
		buf.Write(b[:n])
		if err != nil {
			break
		}
	}
	return []byte(buf.String()), nil
}

func TestChatStateAndInput(t *testing.T) {
	t.Setenv("HARNESS_CHAT_IDLE", "7")
	if chatIdle() != 7e9 {
		t.Fatalf("chat idle: %v", chatIdle())
	}
	t.Setenv("HARNESS_CHAT_IDLE", "")
	if chatIdle() != 10*60e9 {
		t.Fatalf("default chat idle: %v", chatIdle())
	}
	s := newChat("", 0)
	if s.mode != "text" || s.idleFor() != 0 {
		t.Fatalf("defaults: %+v", s)
	}
	s.sawLine(`{"type":"assistant","message":{}}`)
	if s.idleFor() != 0 {
		t.Fatal("an assistant line is not a turn end")
	}
	s.sawLine(`{"type":"result","subtype":"success"}`)
	if s.idleFor() <= 0 {
		t.Fatal("after a result the idle countdown runs")
	}
	s.sent()
	if s.idleFor() != 0 {
		t.Fatal("a message sent resets the countdown until the next turn ends")
	}
}
