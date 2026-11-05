package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"agent-sandbox/internal/catalog"
	"agent-sandbox/internal/model"
)

// The shipped OpenCode profile, as the runner applies it (its harness files written to a clean
// home, its environment), opens a session with the real opencode and the next run loads it.
// It runs where opencode is on PATH (the agent image) or with OPENCODE_TEST_BIN, with loopback
// only (noNetwork); nothing is prompted.
func TestACPOpenCodeExampleCreatesAndLoadsASession(t *testing.T) {
	bin := os.Getenv("OPENCODE_TEST_BIN")
	if bin == "" {
		var err error
		if bin, err = exec.LookPath("opencode"); err != nil {
			t.Skip("install the pinned opencode or set OPENCODE_TEST_BIN to run the OpenCode profile smoke test")
		}
	}
	isolate := noNetwork(t)
	raw, err := os.ReadFile("../../examples/catalog/environment-opencode-acp.yaml")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := catalog.ParseYAML(raw)
	if err != nil {
		t.Fatal(err)
	}
	var profile catalog.EnvironmentSpec
	if err := json.Unmarshal(doc.Spec, &profile); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	files, _ := json.Marshal(profile.Harness.Files)
	if _, err := writeHarnessFiles(string(files), home); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(home, ".config/opencode/opencode.json")); err != nil {
		t.Fatalf("the profile's OpenCode config was not written: %v", err)
	}
	var env []string
	for k, v := range profile.Env {
		env = append(env, k+"="+v)
	}
	t.Setenv("HARNESS_AUTH_METHOD", profile.Harness.AuthMethod)
	t.Setenv("SANDBOX_MCP_SERVERS", "")
	t.Setenv("PWD", home)
	t.Setenv("SANDBOX_REPO_DIR", home+"/no-repo")
	agent := `"` + bin + `" acp`
	if profile.Harness.Command != "opencode acp" {
		t.Fatalf("the example's command is %q; this test runs opencode acp", profile.Harness.Command)
	}
	session, fresh, notices, canLoad := openRealACP(t, isolate, agent, home, env, &model.Run{ID: "run_oc"})
	if !fresh || len(notices) != 0 {
		t.Fatalf("first run: fresh %v, notices %q", fresh, notices)
	}
	if !canLoad {
		t.Fatal("opencode advertises loadSession; the profile relies on it to continue a conversation")
	}
	again, fresh, notices, _ := openRealACP(t, isolate, agent, home, env, &model.Run{ID: "run_oc2", ResumeOf: "run_oc", Session: string(session), Mode: model.RunMessage})
	if fresh || again != session {
		t.Fatalf("the next run must load session %s, got %s (fresh %v); notices %q", session, again, fresh, notices)
	}
}

// The shipped OpenCode profile's model call, from the real opencode through the runner, reaches
// a gateway that requires the pod's client certificate (through the bridge) and its answer
// comes back into the transcript. Runs in the agent image's check or with OPENCODE_TEST_BIN.
func TestACPOpenCodeExampleAnswersThroughTheGateway(t *testing.T) {
	bin := os.Getenv("OPENCODE_TEST_BIN")
	if bin == "" && os.Getenv("ACP_TEST_NETWORK") == "none" {
		bin, _ = exec.LookPath("opencode")
	}
	if bin == "" {
		t.Skip("set OPENCODE_TEST_BIN to run the OpenCode model-call test (it runs by itself in the agent image's check)")
	}
	lines, seen := modelCallThroughGateway(t, "environment-opencode-acp.yaml", "opencode", bin, "api.anthropic.com", anthropicAnswer("pong-from-the-gateway"))
	assertAnswered(t, lines, seen, "pong-from-the-gateway", "api.anthropic.com")
	for _, r := range seen {
		if r.Path == "/v1/messages" && r.APIKey != "placeholder-the-gateway-injects-the-real-key" {
			t.Fatalf("the model call carried %q, not the profile's placeholder key", r.APIKey)
		}
	}
}
