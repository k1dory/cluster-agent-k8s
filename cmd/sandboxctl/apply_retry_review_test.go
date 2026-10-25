package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"agent-sandbox/internal/model"
)

func TestReviewStableKeyRetryRecognizesOwnExpectedRevision(t *testing.T) {
	for _, tc := range []struct {
		name      string
		expected  int
		interrupt bool
	}{
		{"create_partial", 0, true},
		{"create_done", 0, false},
		{"update_partial", 1, true},
		{"update_done", 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, st := realPlatform(t)
			if tc.expected == 1 {
				if apiPut(t, srv.URL, "acme-tok", "/v1/environments/py", `{"spec":{"image":"stable"}}`) != 201 {
					t.Fatal("seed environment")
				}
				if apiPut(t, srv.URL, "acme-tok", "/v1/agents/backend", `{"spec":{"policy":"backend-dev","environment":"py"}}`) != 201 {
					t.Fatal("seed agent")
				}
			}
			repo := t.TempDir()
			run(t, repo, "init", "-q", "-b", "main")
			bundle := fmt.Sprintf("kind: EnvironmentProfile\nname: py\nexpected_revision: %d\nspec: {image: stable, env: {LOG: debug}}\n---\nkind: AgentDefinition\nname: backend\nexpected_revision: %d\ndescription: updated\nspec: {policy: backend-dev, environment: py}\n", tc.expected, tc.expected)
			if err := os.WriteFile(filepath.Join(repo, "bundle.yaml"), []byte(bundle), 0600); err != nil {
				t.Fatal(err)
			}
			run(t, repo, "add", "bundle.yaml")
			run(t, repo, "commit", "-q", "-m", "conditional bundle")
			sha := run(t, repo, "rev-parse", "HEAD")
			key := "bundle.yaml@" + sha
			args := []string{"apply", "-f", "bundle.yaml", "-key", key, "-require-commit", "-markdown"}
			wantFirst := 0
			if tc.interrupt {
				st.arm("backend")
				wantFirst = 3
			}
			_, errOut, code := ctlChild(t, repo, srv.URL, "acme-tok", nil, args...)
			if code != wantFirst {
				t.Fatalf("first apply: exit %d, want %d: %s", code, wantFirst, errOut)
			}
			first, err := st.GetApplyByKey(t.Context(), "acme", key)
			if err != nil {
				t.Fatal(err)
			}
			st.arm("")
			_, _, code = ctlChild(t, repo, srv.URL, "acme-tok", nil, args...)
			if code != 0 {
				t.Errorf("same bundle and stable key must accept its own completed CAS writes; retry exit=%d", code)
			}
			after, err := st.GetApplyByKey(t.Context(), "acme", key)
			if err != nil {
				t.Fatal(err)
			}
			if after.ID != first.ID || after.Status != model.ApplyDone {
				t.Error("retry must finish or return the original apply")
			}
			// The explicit resume control establishes that the saved apply is valid; the
			// failed retry must not be explained as a new external change or revoked right.
			if code != 0 {
				c := &cli{base: srv.URL, token: "acme-tok", http: srv.Client()}
				var resumed model.Apply
				if err := c.do("POST", "/v1/applies/"+first.ID+"/resume", nil, &resumed); err != nil || resumed.Status != model.ApplyDone {
					t.Fatalf("control: explicit resume must succeed: %v, status=%s", err, resumed.Status)
				}
			}
			for _, kind := range []string{model.KindEnvironment, model.KindAgent} {
				name := "py"
				if kind == model.KindAgent {
					name = "backend"
				}
				history, err := st.ListRevisions(t.Context(), kind, "acme", name)
				if err != nil || len(history) != tc.expected+1 {
					t.Errorf("%s must be written exactly once: revisions=%d err=%v", kind, len(history), err)
				}
			}
		})
	}
}

func TestReviewRequireCommitChecksTheSourceActuallySubmitted(t *testing.T) {
	srv, _ := realPlatform(t)
	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, "bundle.yaml"), []byte("kind: EnvironmentProfile\nname: py\nspec: {image: stable}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	_, _, code := ctlChild(t, repo, srv.URL, "acme-tok", nil, "apply", "-f", "bundle.yaml", "-no-git", "-commit", strings.Repeat("a", 40), "-require-commit", "-markdown")
	if code == 0 {
		t.Error("-require-commit must reject -no-git even if an unused explicit commit was supplied")
	}
	if status := apiGet(t, srv.URL, "acme-tok", "/v1/environments/py", nil); status != http.StatusNotFound {
		t.Error("conflicting provenance flags must be rejected before any resource is written")
	}
}
