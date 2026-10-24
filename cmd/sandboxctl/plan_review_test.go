package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestReviewPlanCommandRemainsAvailable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "environment.yaml")
	if err := os.WriteFile(path, []byte("kind: EnvironmentProfile\nname: py\nspec: {image: stable}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/plan" {
			t.Errorf("plan must only call POST /v1/plan: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"valid":true,"bundle":"fixture","plan":"fixture-plan","changes":[],"summary":{}}`)
	}))
	defer srv.Close()
	c := &cli{base: srv.URL, token: "test-token", http: srv.Client()}
	if err := c.run("plan", []string{"-f", path, "-json"}); err != nil {
		t.Fatalf("documented plan command must remain usable: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("expected one plan request, got %d", calls.Load())
	}
}
