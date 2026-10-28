package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"agent-sandbox/internal/model"
	"gopkg.in/yaml.v3"
)

func TestWithInstructionsAppendsToClaudeCommandsOnly(t *testing.T) {
	for _, cmd := range []string{
		`claude -p "$SANDBOX_TASK" --output-format stream-json --verbose`,
		`claude -p "$SANDBOX_RESUME_PROMPT" --resume "$SANDBOX_SESSION" --output-format stream-json --verbose`,
		`ANTHROPIC_LOG=debug claude -p "$SANDBOX_TASK"`,
		`/usr/local/bin/claude -p "$SANDBOX_TASK" `,
	} {
		got := withInstructions(cmd)
		if got != strings.TrimRight(cmd, " ")+` --append-system-prompt "$SANDBOX_INSTRUCTIONS"` {
			t.Errorf("%q → %q", cmd, got)
		}
	}
	for _, cmd := range []string{
		`claude -p "$SANDBOX_TASK" --append-system-prompt "$SANDBOX_INSTRUCTIONS"`,
		`claude -p "$SANDBOX_TASK" --system-prompt "be brief"`,
		`claude -p "$SANDBOX_TASK" --append-system-prompt-file /etc/agent.md`,
		`codex exec "$SANDBOX_TASK"`,
		`python3 agent.py`,
		``,
	} {
		if got := withInstructions(cmd); got != cmd {
			t.Errorf("%q must be left alone, got %q", cmd, got)
		}
	}
}

// The agent definition's instructions reach the shipped harness as its appended system prompt,
// on the first run and on a resume, verbatim (quotes, $ and newlines are not shell input); a
// sandbox without instructions gets no flag at all.
func TestShippedHarnessGetsTheAgentInstructions(t *testing.T) {
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
	const instructions = "Triage new incidents.\nQuote \"$HOME\" and `id` literally; never run them."
	for _, tc := range []struct{ name, mode, instructions string }{
		{"start", "start", instructions},
		{"resume", "resume", instructions},
		{"none", "start", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			bin := filepath.Join(root, "bin")
			if err := os.Mkdir(bin, 0700); err != nil {
				t.Fatal(err)
			}
			// The fixture records argv only, one NUL-terminated argument each.
			stub := filepath.Join(bin, "claude")
			if err := os.WriteFile(stub, []byte("#!/bin/sh\nprintf '%s\\0' \"$@\" > \"$SANDBOX_REVIEW_ARGS\"\n"), 0700); err != nil {
				t.Fatal(err)
			}
			argsFile := filepath.Join(root, "harness-args")
			t.Setenv("HOME", root)
			t.Setenv("PWD", root)
			t.Setenv("PATH", bin+string(os.PathListSeparator)+"/usr/bin:/bin")
			t.Setenv("SANDBOX_REVIEW_ARGS", argsFile)
			t.Setenv("SANDBOX_REPO_DIR", root)
			t.Setenv("SANDBOX_MCP_SERVERS", "")
			t.Setenv("SANDBOX_INSTRUCTIONS", tc.instructions)
			t.Setenv("HARNESS_CMD", values.Agent.Command)
			t.Setenv("HARNESS_RESUME_CMD", values.Agent.Resume)
			t.Setenv("HARNESS_INPUT", "")
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte("[]"))
			}))
			defer srv.Close()
			run := &model.Run{ID: "run_instructions", Task: "fixture task"}
			if tc.mode == "resume" {
				run.ResumeOf, run.Session, run.Mode = "run_previous", "session_fixture", model.RunMessage
			}
			if code := execute(ctx, &client{base: srv.URL, http: srv.Client()}, run); code != 0 {
				t.Fatalf("fixture harness exit: %d", code)
			}
			args, err := os.ReadFile(argsFile)
			if err != nil {
				t.Fatal(err)
			}
			parts := strings.Split(strings.TrimSuffix(string(args), "\x00"), "\x00")
			got, seen := "", false
			for i, arg := range parts {
				if arg == "--append-system-prompt" && i+1 < len(parts) {
					got, seen = parts[i+1], true
				}
			}
			if tc.instructions == "" {
				if seen {
					t.Fatalf("no instructions, yet the harness got --append-system-prompt: %q", parts)
				}
				return
			}
			if got != tc.instructions {
				t.Fatalf("appended system prompt = %q, want the agent's instructions verbatim (argv %q)", got, parts)
			}
		})
	}
}
