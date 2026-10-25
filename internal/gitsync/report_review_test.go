package gitsync

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"agent-sandbox/internal/render"
)

// A platform comment can be beyond the first page of a busy PR/MR.
func TestReviewReporterFindsExistingCommentOnLaterPage(t *testing.T) {
	for _, provider := range []string{ProviderGitHub, ProviderGitLab} {
		t.Run(provider, func(t *testing.T) {
			var created, updated, pages atomic.Int64
			var srv *httptest.Server
			srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.Method {
				case http.MethodGet:
					pages.Add(1)
					if r.URL.Query().Get("page") == "2" {
						json.NewEncoder(w).Encode([]map[string]any{{"id": 501, "body": render.Marker + "\nprevious plan"}})
						return
					}
					w.Header().Set("Link", fmt.Sprintf("<%s%s?per_page=100&page=2>; rel=\"next\"", srv.URL, r.URL.EscapedPath()))
					w.Header().Set("X-Next-Page", "2")
					comments := make([]map[string]any, 100)
					for i := range comments {
						comments[i] = map[string]any{"id": i + 1, "body": "discussion"}
					}
					json.NewEncoder(w).Encode(comments)
				case http.MethodPost:
					created.Add(1)
					fmt.Fprint(w, `{"id":502}`)
				case http.MethodPatch, http.MethodPut:
					if strings.HasSuffix(r.URL.Path, "/501") {
						updated.Add(1)
					}
					fmt.Fprint(w, `{"id":501}`)
				default:
					w.WriteHeader(http.StatusMethodNotAllowed)
				}
			}))
			defer srv.Close()
			reporter := RESTReporter{Client: srv.Client()}
			target := Target{Provider: provider, APIBase: srv.URL, Repo: "acme/config", Number: 7, SHA: sha1, Token: "fixture"}
			if err := reporter.UpsertComment(t.Context(), target, render.Marker+"\nupdated plan"); err != nil {
				t.Fatal(err)
			}
			if created.Load() != 0 || updated.Load() != 1 {
				t.Fatalf("existing comment on page 2 must be updated: pages=%d created=%d updated=%d", pages.Load(), created.Load(), updated.Load())
			}
		})
	}
}
