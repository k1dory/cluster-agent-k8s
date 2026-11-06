package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"agent-sandbox/internal/catalog"
	"agent-sandbox/internal/harness"
	"agent-sandbox/internal/model"
	"github.com/k1dory/acpx"
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
	args, ok := strings.CutPrefix(profile.Harness.Command, program+" acp")
	if !ok {
		t.Fatalf("the example's command is %q; this test runs %s acp", profile.Harness.Command, program)
	}
	home := t.TempDir()
	t.Cleanup(func() { logProcesses(t, home) })
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
	// The profile's mode and model are applied to the real agent: a notice would say it does
	// not offer them (the first run must have none).
	t.Setenv("HARNESS_MODE", profile.Harness.Mode)
	t.Setenv("HARNESS_MCP", profile.Harness.MCP)
	t.Setenv("SANDBOX_MODEL", profile.Model.Name)
	t.Setenv("HARNESS_THOUGHT_LEVEL", profile.Harness.ThoughtLevel)
	meta, _ := json.Marshal(profile.Harness.SessionMeta)
	if len(profile.Harness.SessionMeta) == 0 {
		meta = nil
	}
	t.Setenv("HARNESS_SESSION_META", string(meta))
	t.Setenv("SANDBOX_INSTRUCTIONS", "")
	t.Setenv("SANDBOX_MCP_SERVERS", "")
	t.Setenv("PWD", home)
	t.Setenv("SANDBOX_REPO_DIR", home+"/no-repo")
	agent := `"` + bin + `" acp` + args
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
	// The instructions reach OpenCode's system prompt through the file its configuration names
	// (harness.instructions: file), not the first prompt.
	handler, check := systemPromptRecorder(anthropicAnswer("pong-from-the-gateway"))
	lines, seen := modelCallThroughGateway(t, "environment-opencode-acp.yaml", "opencode", bin, "api.anthropic.com", handler,
		func(string) map[string]string { return map[string]string{"SANDBOX_INSTRUCTIONS": instructionMarker} })
	assertAnswered(t, lines, seen, "pong-from-the-gateway", "api.anthropic.com")
	for _, r := range seen {
		if r.Path == "/v1/messages" && r.APIKey != "placeholder-the-gateway-injects-the-real-key" {
			t.Fatalf("the model call carried %q, not the profile's placeholder key", r.APIKey)
		}
	}
	check(t)
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
	// The instructions reach Hermes's system prompt as its environment hint
	// (harness.instructions: env:HERMES_ENVIRONMENT_HINT), not the first prompt.
	handler, check := systemPromptRecorder(anthropicAnswer("pong-from-the-gateway"))
	lines, seen := modelCallThroughGateway(t, "environment-hermes-acp.yaml", "hermes", bin, "api.anthropic.com", handler,
		func(home string) map[string]string {
			return map[string]string{"HERMES_HOME": filepath.Join(home, ".hermes"), "SANDBOX_INSTRUCTIONS": instructionMarker}
		})
	assertAnswered(t, lines, seen, "pong-from-the-gateway", "api.anthropic.com")
	check(t)
}

// The shipped claude-acp profile against the real adapter: it declares the client system prompt,
// takes the instructions as one in session/new (the request is refused if the field is wrong),
// and accepts the profile's mode. Nothing is prompted. Runs in the agent image's check or with
// CLAUDE_AGENT_ACP_TEST_BIN.
func TestACPClaudeExampleTakesTheSystemPromptAndMode(t *testing.T) {
	bin := os.Getenv("CLAUDE_AGENT_ACP_TEST_BIN")
	if bin == "" && os.Getenv("ACP_TEST_NETWORK") == "none" {
		bin, _ = exec.LookPath("claude-agent-acp")
	}
	if bin == "" {
		t.Skip("set CLAUDE_AGENT_ACP_TEST_BIN to run the claude-acp profile check (it runs by itself in the agent images' check)")
	}
	isolate := noNetwork(t)
	raw, err := os.ReadFile("../../examples/catalog/environment-claude-acp.yaml")
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
	t.Cleanup(func() { logProcesses(t, home) })
	files, _ := json.Marshal(profile.Harness.Files)
	if _, err := writeHarnessFiles(string(files), home); err != nil {
		t.Fatal(err)
	}
	var env []string
	for k, v := range profile.Env {
		env = append(env, k+"="+v)
	}
	t.Setenv("HARNESS_AUTH_METHOD", profile.Harness.AuthMethod)
	t.Setenv("HARNESS_MODE", profile.Harness.Mode)
	t.Setenv("HARNESS_MCP", "")
	t.Setenv("SANDBOX_MODEL", "") // the adapter's model aliases are not the profile's names; ANTHROPIC_MODEL selects it
	t.Setenv("SANDBOX_INSTRUCTIONS", "Answer in one word.")
	t.Setenv("SANDBOX_MCP_SERVERS", "")
	t.Setenv("PWD", home)
	t.Setenv("SANDBOX_REPO_DIR", home+"/no-repo")

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, isolate[0], append(isolate[1:], bin)...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.Dir = home
	cmd.Env = append(append(os.Environ(), "HOME="+home), env...)
	cmd.WaitDelay = 2 * time.Second
	var stderr strings.Builder
	cmd.Stderr = &stderr
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer stopAdapter(stdin, cancel, cmd, home)
	var notices []string
	emit := func(l string) {
		if strings.HasPrefix(l, "[agent-runner] ") { // a notice; ACP lines (acp.commands…) are output
			notices = append(notices, l)
		}
	}
	// The runner's own wiring: notices and compaction updates asked for, the profile's session
	// options in _meta (the adapter refuses options it cannot take).
	wire := acpx.NewWire(stdin, stdout, acpx.WireOptions{Notices: true, Compaction: true})
	// A person answers (permissions ask): the client offers elicitation, which the adapter takes.
	cl := &acpClient{emit: emit, wire: wire, systemPrompt: wire.SystemPrompt, permissions: harness.PermissionsAsk}
	conn := wire.Connect(cl)
	meta, _ := json.Marshal(profile.Harness.SessionMeta)
	t.Setenv("HARNESS_SESSION_META", string(meta))
	s, ok := openACPSession(ctx, conn, cl, &model.Run{ID: "run_claude"}, emit)
	switch {
	case !ok:
		t.Fatalf("no session: %q\nadapter stderr:\n%s", notices, stderr.String())
	case !wire.SystemPrompt() || !s.instructions:
		t.Fatalf("the adapter's system prompt was not used (capability %v)", wire.SystemPrompt())
	case len(notices) != 0:
		t.Fatalf("notices: %q", notices)
	}
}

const instructionMarker = "Instruction-marker-7f3a: answer in one word."

// systemPromptRecorder wraps a Messages API and checks, after the run, that the instruction marker
// was in a request's system prompt and in none of its messages.
func systemPromptRecorder(answer http.Handler) (http.Handler, func(t *testing.T)) {
	var mu sync.Mutex
	var system, messages []string
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			System   json.RawMessage `json:"system"`
			Messages json.RawMessage `json:"messages"`
		}
		if json.Unmarshal(body, &req) == nil && strings.HasSuffix(r.URL.Path, "/v1/messages") {
			mu.Lock()
			system, messages = append(system, string(req.System)), append(messages, string(req.Messages))
			mu.Unlock()
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		answer.ServeHTTP(w, r)
	})
	return h, func(t *testing.T) {
		t.Helper()
		mu.Lock()
		defer mu.Unlock()
		inSystem := strings.Contains(strings.Join(system, "\n"), "Instruction-marker-7f3a")
		inMessages := strings.Contains(strings.Join(messages, "\n"), "Instruction-marker-7f3a")
		if !inSystem || inMessages {
			t.Fatalf("the instructions must be in the system prompt only: %d model call(s), in the system prompt %v, in the messages %v", len(system), inSystem, inMessages)
		}
	}
}
