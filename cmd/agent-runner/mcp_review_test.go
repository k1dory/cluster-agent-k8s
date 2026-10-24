package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"agent-sandbox/internal/model"
	"gopkg.in/yaml.v3"
)

func TestReviewShippedHarnessLoadsMCPOnStartAndResume(t *testing.T) {
	raw, err := os.ReadFile("../../deploy/helm/agent-sandbox/values.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var values struct {
		Agent struct {
			Command string `yaml:"harnessCommand"`
			Resume  string `yaml:"harnessResumeCommand"`
		} `yaml:"agent"`
	}
	if err := yaml.Unmarshal(raw, &values); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"start", "resume"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			bin := filepath.Join(root, "bin")
			if err := os.Mkdir(bin, 0700); err != nil {
				t.Fatal(err)
			}
			// The fixture records argv only; no LLM process or external request is started.
			stub := filepath.Join(bin, "claude")
			if err := os.WriteFile(stub, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$SANDBOX_REVIEW_ARGS\"\n"), 0700); err != nil {
				t.Fatal(err)
			}
			argsFile := filepath.Join(root, "harness-args")
			t.Setenv("HOME", root) // isolated home of the fixture agent
			t.Setenv("PWD", root)
			t.Setenv("PATH", bin+string(os.PathListSeparator)+"/usr/bin:/bin")
			t.Setenv("SANDBOX_REVIEW_ARGS", argsFile)
			t.Setenv("SANDBOX_REPO_DIR", root)
			t.Setenv("SANDBOX_MCP_SERVERS", `[{"name":"tools","url":"https://tools.review.example.com/mcp"}]`)
			t.Setenv("HARNESS_CMD", values.Agent.Command)
			t.Setenv("HARNESS_RESUME_CMD", values.Agent.Resume)
			t.Setenv("HARNESS_INPUT", "")
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			selected, err := exec.CommandContext(ctx, "/bin/sh", "-lc", "command -v claude").Output()
			if err != nil || strings.TrimSpace(string(selected)) != stub {
				t.Fatal("test setup: login shell must select the fixture harness")
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte("[]"))
			}))
			defer srv.Close()
			run := &model.Run{ID: "run_review_mcp", Task: "fixture task"}
			if mode == "resume" {
				run.ResumeOf, run.Session, run.Mode = "run_previous", "session_fixture", model.RunMessage
			}
			if code := execute(ctx, &client{base: srv.URL, http: srv.Client()}, run); code != 0 {
				t.Fatalf("fixture harness exit: %d", code)
			}
			args, err := os.ReadFile(argsFile)
			if err != nil {
				t.Fatal(err)
			}
			parts := strings.Split(strings.TrimSpace(string(args)), "\n")
			loaded := ""
			for i, arg := range parts {
				if arg == "--mcp-config" && i+1 < len(parts) {
					loaded = parts[i+1]
				}
			}
			if loaded == "" {
				t.Fatal("the shipped harness must load the generated MCP configuration")
			}
			if config, err := os.ReadFile(loaded); err != nil || !strings.Contains(string(config), "tools.review.example.com") {
				t.Fatal("the harness must receive the configuration of the sandbox's MCP servers")
			}
		})
	}
}
