package httpapi

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// Reject malformed or oversized input before any Git read or catalogue write.
func TestReviewGitSyncRequiresOneCompleteJSONBody(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"two_documents", "{} {}"},
		{"body_larger_than_reader", strings.Repeat(" ", 4096) + `{"commit":"not-a-sha"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, git, _ := gitStack(t)
			git.repos["https://git.example.com/alice/config.git"] = &fakeRepo{
				heads: map[string]string{"main": shaA}, history: map[string][]string{"main": {shaA}},
				files: map[string]map[string][]byte{shaA: {"bundle.yaml": []byte("kind: EnvironmentProfile\nname: py\nspec: {image: stable}\n")}},
			}
			doc := `{"spec":{"url":"https://git.example.com/alice/config.git","ref":"main","paths":["bundle.yaml"]}}`
			if code, _ := putDoc(t, s.platform.URL, "alice-tok", "gitrepos", "config", doc); code != http.StatusCreated {
				t.Fatalf("register: %d", code)
			}
			req, err := http.NewRequest("POST", s.platform.URL+"/v1/gitrepos/config/sync", strings.NewReader(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer alice-tok")
			req.Header.Set("Content-Type", "application/json")
			resp, err := s.platform.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusRequestEntityTooLarge {
				t.Errorf("incomplete request validation: status=%d body=%s", resp.StatusCode, body)
			}
			if len(git.seen) != 0 {
				t.Errorf("invalid input reached Git: %d reads", len(git.seen))
			}
			applies, err := s.orch.Store.ListApplies(t.Context(), "alice", 100)
			if err != nil || len(applies) != 0 {
				t.Errorf("invalid input must not create applies: count=%d err=%v", len(applies), err)
			}
		})
	}
}
