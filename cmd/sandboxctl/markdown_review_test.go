package main

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"agent-sandbox/internal/model"
	"agent-sandbox/internal/plan"
)

func TestReviewMarkdownDiffPreservesTableShape(t *testing.T) {
	var out bytes.Buffer
	p := plan.Plan{Valid: true, Summary: plan.Summary{Update: 1}, Changes: []plan.Change{
		{Kind: model.KindEnvironment, Tenant: "acme", Name: "python", Action: plan.ActionUpdate, CurrentRevision: 1, NextRevision: 2,
			Diff: []plan.FieldChange{{Path: "spec.instructions", From: "build", To: "build | test\npackage"}}},
	}}
	markdownPlan(&out, p, "bundle.yaml")
	if !strings.Contains(out.String(), `build \| test`) {
		t.Error("a pipe in an ordinary diff value must not create another Markdown table cell")
	}
	if strings.Contains(out.String(), "test\npackage") {
		t.Error("a multiline instruction must not split the Markdown table row")
	}
}

func TestReviewInvalidApplyStillRendersMarkdown(t *testing.T) {
	file := filepath.Join(t.TempDir(), "bundle.yaml")
	if err := os.WriteFile(file, []byte("kind: EnvironmentProfile\nname: python\nspec: {image: stable}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/v1/plan" {
			t.Error("invalid plan must not be submitted to apply")
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"valid":false,"errors":["environment is no longer allowed"],"summary":{"invalid":1},"changes":[]}`))
	}))
	defer srv.Close()
	out, err := reviewCredentialsCLI(t, srv.URL, "SANDBOXD_TOKEN", "", "apply", "-f", file, "-no-git", "-markdown")
	var exited *exec.ExitError
	if !errors.As(err, &exited) || exited.ExitCode() != 2 {
		t.Fatalf("invalid apply must exit 2: %v", err)
	}
	if !strings.HasPrefix(string(out), Marker+"\n") {
		t.Error("apply -markdown must preserve the Markdown marker and report when its plan is invalid")
	}
}
