package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"agent-sandbox/internal/model"
)

// A write whose parent directory is a symlink out of the workspace must not create a file
// outside; the same for reads and listings through such a link, and for links to files.
func TestWorkspaceBoundaryHoldsForNewFiles(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	_ = os.WriteFile(filepath.Join(outside, "secret"), []byte("s"), 0o644)
	_ = os.Symlink(outside, filepath.Join(root, "linkdir"))
	_ = os.Symlink(filepath.Join(outside, "secret"), filepath.Join(root, "linkfile"))
	_ = os.MkdirAll(filepath.Join(root, "nested"), 0o755)
	_ = os.Symlink("../../"+filepath.Base(outside), filepath.Join(root, "nested", "rel"))
	blobs := map[string][]byte{"fs/sb/in": []byte("payload")}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if b, ok := blobs["fs/sb/in"]; ok && r.Method == http.MethodGet {
			w.Write(b)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"name": "fs/sb/out"})
	}))
	defer server.Close()
	c := &client{base: server.URL, http: server.Client()}
	ctx := context.Background()
	for _, req := range []model.FSRequest{
		{Op: model.FSRead, Path: "linkdir/secret"},
		{Op: model.FSRead, Path: "linkfile"},
		{Op: model.FSList, Path: "linkdir"},
		{Op: model.FSList, Path: "nested/rel"},
		{Op: model.FSWrite, Path: "linkdir/new.txt", Blob: "fs/sb/in"},
		{Op: model.FSWrite, Path: "linkdir/deeper/new.txt", Blob: "fs/sb/in"},
		{Op: model.FSWrite, Path: "nested/rel/new.txt", Blob: "fs/sb/in"},
		{Op: model.FSWrite, Path: "../escape.txt", Blob: "fs/sb/in"},
		{Op: model.FSWrite, Path: "repo/../../escape.txt", Blob: "fs/sb/in"},
		{Op: model.FSWrite, Path: "", Blob: "fs/sb/in"},
	} {
		if res := c.serveFile(ctx, root, req); res.OK {
			t.Errorf("%+v must be refused", req)
		}
	}
	for _, p := range []string{"new.txt", "deeper/new.txt", "escape.txt"} {
		if _, err := os.Stat(filepath.Join(outside, p)); err == nil {
			t.Errorf("%s was written outside the workspace", p)
		}
	}
	// Writing over a symlink to an outside file replaces the link inside the workspace; the
	// file it pointed to is untouched.
	if res := c.serveFile(ctx, root, model.FSRequest{Op: model.FSWrite, Path: "linkfile", Blob: "fs/sb/in"}); !res.OK {
		t.Fatalf("write over a link: %+v", res)
	}
	if b, _ := os.ReadFile(filepath.Join(outside, "secret")); string(b) != "s" {
		t.Fatal("the file behind the link was overwritten")
	}
	if fi, err := os.Lstat(filepath.Join(root, "linkfile")); err != nil || fi.Mode()&os.ModeSymlink != 0 {
		t.Fatal("the link must have been replaced by a regular file inside the workspace")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(root), "escape.txt")); err == nil {
		t.Fatal("escape.txt was written beside the workspace")
	}
	// Inside the workspace, relative links that stay inside and plain paths keep working.
	_ = os.Symlink("nested", filepath.Join(root, "inner"))
	if res := c.serveFile(ctx, root, model.FSRequest{Op: model.FSWrite, Path: "inner/ok.txt", Blob: "fs/sb/in"}); !res.OK {
		t.Fatalf("link inside the workspace: %+v", res)
	}
	if b, err := os.ReadFile(filepath.Join(root, "nested", "ok.txt")); err != nil || string(b) != "payload" {
		t.Fatalf("write through an inner link: %v %q", err, b)
	}
	if res := c.serveFile(ctx, root, model.FSRequest{Op: model.FSList, Path: "/workspace/", Depth: 2}); !res.OK || len(res.Entries) == 0 {
		t.Fatalf("list root: %+v", res)
	}
}

// A result refused by a transient failure is delivered again; the cursor moves only after the
// control plane acknowledged it.
func TestFileResultSurvivesTransientFailure(t *testing.T) {
	root := t.TempDir()
	_ = os.WriteFile(filepath.Join(root, "a.txt"), []byte("A"), 0o644)
	var polls, results, acked atomic.Int32
	req := model.FSRequest{ID: "fs_1", Op: model.FSList, Path: ""}
	data, _ := json.Marshal(req)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/agent/fs/requests":
			n := polls.Add(1)
			after := r.URL.Query().Get("after")
			// Until the answer is acknowledged the request is still pending and is served again.
			if acked.Load() == 0 || after == "0" {
				if n > 1 && acked.Load() > 0 && after != "0" {
					_ = json.NewEncoder(w).Encode([]model.Event{})
					return
				}
				_ = json.NewEncoder(w).Encode([]model.Event{{ID: 7, Type: model.EventFSRequest, Data: string(data)}})
				return
			}
			time.Sleep(50 * time.Millisecond)
			_ = json.NewEncoder(w).Encode([]model.Event{})
		case "/agent/fs/results":
			var res model.FSResult
			_ = json.NewDecoder(r.Body).Decode(&res)
			if res.Request != "fs_1" || !res.OK {
				t.Errorf("unexpected result %+v", res)
			}
			if results.Add(1) == 1 {
				http.Error(w, "temporary outage", http.StatusServiceUnavailable)
				return
			}
			acked.Add(1)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "unexpected "+r.URL.Path, http.StatusNotFound)
		}
	}))
	defer server.Close()
	c := &client{base: server.URL, http: server.Client()}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { serveFiles(ctx, c, root); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for acked.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	// Give the loop one more poll: it must now ask after the acknowledged event, not repeat it.
	time.Sleep(200 * time.Millisecond)
	cancel()
	<-done
	if acked.Load() != 1 || results.Load() < 2 {
		t.Fatalf("results=%d acked=%d: the answer must be retried until acknowledged", results.Load(), acked.Load())
	}
	if results.Load() > 2 {
		t.Fatalf("an acknowledged answer was sent again (%d results)", results.Load())
	}
}
