package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	acp "github.com/coder/acp-go-sdk"

	"agent-sandbox/internal/harness"
	"agent-sandbox/internal/model"
	"gopkg.in/yaml.v3"
)

// The chart's default harness is Claude over ACP, and the sandbox's MCP servers reach it in the
// session on start and when the next run continues the conversation, by their gateway bridge
// URLs. The agent here is the scripted one; the shipped settings come from the chart's values.
func TestReviewShippedHarnessLoadsMCPOnStartAndResume(t *testing.T) {
	raw, err := os.ReadFile("../../deploy/helm/agent-sandbox/values.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var values struct {
		Agent struct {
			Command     string `yaml:"harnessCommand"`
			Input       string `yaml:"harnessInput"`
			Permissions string `yaml:"harnessPermissions"`
			Mode        string `yaml:"harnessMode"`
			Resume      string `yaml:"harnessResumeCommand"`
		} `yaml:"agent"`
	}
	if err := yaml.Unmarshal(raw, &values); err != nil {
		t.Fatal(err)
	}
	a := values.Agent
	if a.Command != "claude-agent-acp" || a.Input != harness.InputACP || a.Permissions != "allow" || a.Mode != "default" || a.Resume != "" {
		t.Fatalf("the chart's default harness must be Claude over ACP: %+v", a)
	}

	want := "http://127.0.0.1:4480/https/tools.review.example.com/mcp"
	seen := map[string]bool{}
	// Each run talks to a control plane of its own (one conversation each).
	for _, run := range []*model.Run{
		{ID: "run_review_mcp", Task: "fixture task"},
		{ID: "run_review_next", Task: "next", ResumeOf: "run_review_mcp", Session: "sess_new", Mode: model.RunMessage},
	} {
		agentLog, _, cl := setupACP(t, a.Permissions)
		t.Setenv("HARNESS_INPUT", a.Input)
		t.Setenv("HARNESS_MODE", "") // the scripted agent has no modes; the real adapter's is checked in acp_examples_test.go
		t.Setenv("SANDBOX_MCP_SERVERS", `[{"name":"tools","url":"https://tools.review.example.com/mcp"}]`)
		if code := runACP(t, cl, run); code != 0 {
			t.Fatalf("%s: exit %d", run.ID, code)
		}
		for _, r := range readAgentLog(t, agentLog) {
			if r.Kind != "new" && r.Kind != "load" {
				continue
			}
			var req struct {
				McpServers []acp.McpServer `json:"mcpServers"`
			}
			if err := json.Unmarshal(r.V, &req); err != nil {
				t.Fatal(err)
			}
			for _, s := range req.McpServers {
				if s.Http != nil && s.Http.Name == "tools" && strings.EqualFold(s.Http.Url, want) {
					seen[r.Kind] = true
				}
			}
		}
	}
	if !seen["new"] || !seen["load"] {
		t.Fatalf("the MCP server must reach the session on start and on load: %v", seen)
	}
}

// A pod without a configured harness runs claude-agent-acp over ACP, not claude -p; a configured
// one is left as it is.
func TestRunnerDefaultHarnessIsClaudeOverACP(t *testing.T) {
	for _, c := range []struct{ cmd, input, wantCmd, wantInput string }{
		{"", "", "claude-agent-acp", harness.InputACP},
		{"", harness.InputText, "claude-agent-acp", harness.InputText},
		{`claude -p "$SANDBOX_TASK"`, "", `claude -p "$SANDBOX_TASK"`, ""},
		{"codex-acp", harness.InputACP, "codex-acp", harness.InputACP},
	} {
		if cmd, input := harnessOf(c.cmd, c.input); cmd != c.wantCmd || input != c.wantInput {
			t.Errorf("harnessOf(%q, %q) = %q, %q", c.cmd, c.input, cmd, input)
		}
	}
}
