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
// It runs in the agent image's check (hack/ci/images.sh) or with OPENCODE_TEST_BIN, with loopback
// only (noNetwork); nothing is prompted.
func TestACPOpenCodeExampleCreatesAndLoadsASession(t *testing.T) {
	exampleSmoke(t, "environment-opencode-acp.yaml", "OPENCODE_TEST_BIN", "opencode", nil)
}

// The shipped Hermes profile, the same way, with the real hermes of the agent-hermes image (or
// HERMES_TEST_BIN). Hermes's state goes to $HERMES_HOME, which the image puts in the agent's
// home; here that home is the test's.
func TestACPHermesExampleCreatesAndLoadsASession(t *testing.T) {
	exampleSmoke(t, "environment-hermes-acp.yaml", "HERMES_TEST_BIN", "hermes", func(home string) []string {
		return []string{"HERMES_HOME=" + filepath.Join(home, ".hermes")}
	})
}

// exampleSmoke applies examples/catalog/<file> to a clean home and checks, against the real agent
// program, that the runner's session setup opens a session without notices and that a second
// process — the next run — loads it. The profile's command must be "<program> acp".
func exampleSmoke(t *testing.T, file, binEnv, program string, extraEnv func(home string) []string) {
	t.Helper()
	// The program is taken from PATH only inside an agent image (hack/ci/images.sh, which also
	// cuts the network): on a workstation a locally installed one may be another version or
	// build (a hermes without its acp extra, say), so it is named explicitly there.
	bin := os.Getenv(binEnv)
	if bin == "" && os.Getenv("ACP_TEST_NETWORK") == "none" {
		bin, _ = exec.LookPath(program)
	}
	if bin == "" {
		t.Skipf("set %s to run the %s profile smoke test (it runs by itself in the agent images' check)", binEnv, program)
	}
	isolate := noNetwork(t)
	raw, err := os.ReadFile(filepath.Join("../../examples/catalog", file))
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
	if profile.Harness.Command != program+" acp" {
		t.Fatalf("the example's command is %q; this test runs %s acp", profile.Harness.Command, program)
	}
	home := t.TempDir()
	files, _ := json.Marshal(profile.Harness.Files)
	if n, err := writeHarnessFiles(string(files), home); err != nil || n != len(profile.Harness.Files) {
		t.Fatalf("the profile's harness files: %d written, %v", n, err)
	}
	var env []string
	for k, v := range profile.Env {
		env = append(env, k+"="+v)
	}
	if extraEnv != nil {
		env = append(env, extraEnv(home)...)
	}
	t.Setenv("HARNESS_AUTH_METHOD", profile.Harness.AuthMethod)
	t.Setenv("SANDBOX_MCP_SERVERS", "")
	t.Setenv("PWD", home)
	t.Setenv("SANDBOX_REPO_DIR", home+"/no-repo")
	agent := `"` + bin + `" acp`
	session, fresh, notices, canLoad := openRealACP(t, isolate, agent, home, env, &model.Run{ID: "run_example"})
	if !fresh || len(notices) != 0 {
		t.Fatalf("first run: fresh %v, notices %q", fresh, notices)
	}
	if !canLoad {
		t.Fatalf("%s does not advertise loadSession; the profile relies on it to continue a conversation", program)
	}
	again, fresh, notices, _ := openRealACP(t, isolate, agent, home, env, &model.Run{ID: "run_example_next", ResumeOf: "run_example", Session: string(session), Mode: model.RunMessage})
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
	if runOfflineInNetns(t) {
		return
	}
	lines, seen := modelCallThroughGateway(t, "environment-opencode-acp.yaml", "opencode", bin, "api.anthropic.com", anthropicAnswer("pong-from-the-gateway"))
	assertAnswered(t, lines, seen, "pong-from-the-gateway", "api.anthropic.com")
	for _, r := range seen {
		if r.Path == "/v1/messages" && r.APIKey != "placeholder-the-gateway-injects-the-real-key" {
			t.Fatalf("the model call carried %q, not the profile's placeholder key", r.APIKey)
		}
	}
}

// The shipped Hermes profile's model call, from the real hermes of the agent-hermes image
// through the runner, reaches a gateway that requires the pod's client certificate (through the
// bridge, ANTHROPIC_BASE_URL) and its answer comes back into the transcript.
func TestACPHermesExampleAnswersThroughTheGateway(t *testing.T) {
	bin := os.Getenv("HERMES_TEST_BIN")
	if bin == "" && os.Getenv("ACP_TEST_NETWORK") == "none" {
		bin, _ = exec.LookPath("hermes")
	}
	if bin == "" {
		t.Skip("set HERMES_TEST_BIN to run the Hermes model-call test (it runs by itself in the agent-hermes image's check)")
	}
	if runOfflineInNetns(t) {
		return
	}
	// The image puts HERMES_HOME in the agent's home; here that home is the test's.
	lines, seen := modelCallThroughGateway(t, "environment-hermes-acp.yaml", "hermes", bin, "api.anthropic.com", anthropicAnswer("pong-from-the-gateway"),
		func(home string) map[string]string {
			return map[string]string{"HERMES_HOME": filepath.Join(home, ".hermes")}
		})
	assertAnswered(t, lines, seen, "pong-from-the-gateway", "api.anthropic.com")
}
