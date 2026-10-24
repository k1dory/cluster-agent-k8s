package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"agent-sandbox/internal/model"
)

func TestReviewNewFilePathsStayWithinWorkspace(t *testing.T) {
	root, separateDirectory := t.TempDir(), t.TempDir()
	if err := os.Symlink(separateDirectory, filepath.Join(root, "linked-directory")); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("test fixture"))
	}))
	defer server.Close()
	c := &client{base: server.URL, http: server.Client()}
	if res := c.serveFile(t.Context(), root, model.FSRequest{ID: "inside", Op: model.FSWrite, Path: "new-file.txt", Blob: "fixture"}); !res.OK {
		t.Fatalf("a new file inside the workspace must remain supported: %s", res.Error)
	}
	// Both directories are disposable test fixtures; only the workspace may change.
	if res := c.serveFile(t.Context(), root, model.FSRequest{ID: "outside", Op: model.FSWrite, Path: "linked-directory/new-file.txt", Blob: "fixture"}); res.OK {
		t.Fatal("a new file whose parent resolves outside the workspace must be rejected")
	}
	if _, err := os.Stat(filepath.Join(separateDirectory, "new-file.txt")); !os.IsNotExist(err) {
		t.Fatalf("the separate fixture directory must remain unchanged: %v", err)
	}
}

func TestReviewFilesRetryResultBeforeAdvancingCursor(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 6*time.Second)
	defer cancel()
	var posted atomic.Int32
	var acknowledged, advancedBeforeAck atomic.Bool
	request, err := json.Marshal(model.FSRequest{ID: "review-request", Op: model.FSList, Path: ".", Depth: 1})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/agent/fs/requests":
			after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
			if after >= 1 {
				if !acknowledged.Load() {
					advancedBeforeAck.Store(true)
				}
				cancel()
				_ = json.NewEncoder(w).Encode([]model.Event{})
				return
			}
			_ = json.NewEncoder(w).Encode([]model.Event{{ID: 1, Type: model.EventFSRequest, Data: string(request)}})
		case "/agent/fs/results":
			if posted.Add(1) == 1 {
				http.Error(w, "temporary test failure", http.StatusServiceUnavailable)
				return
			}
			acknowledged.Store(true)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	serveFiles(ctx, &client{base: server.URL, http: server.Client()}, t.TempDir())
	if advancedBeforeAck.Load() {
		t.Fatal("file request cursor advanced after a rejected result; the waiting client will receive no answer")
	}
	if !acknowledged.Load() {
		t.Fatal("the transiently rejected file result was not acknowledged after retry")
	}
}
