package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	acp "github.com/coder/acp-go-sdk"

	"agent-sandbox/internal/catalog"
)

// This smoke test needs the real adapter, not a mock of its authentication
// behavior. It runs automatically when codex-acp is on PATH (e.g. in the agent
// image), or with CODEX_ACP_TEST_BIN=/absolute/path/to/codex-acp. An optional
// CODEX_ACP_TEST_CODEX_PATH selects the exact Codex binary under test.
// No prompt is sent and no real API key or existing login is used. The adapter
// and its children run without outbound network access; if isolation is not
// available, the test is skipped.
func TestACPCodexExampleCreatesSession(t *testing.T) {
	adapter := os.Getenv("CODEX_ACP_TEST_BIN")
	if adapter == "" {
		var err error
		adapter, err = exec.LookPath("codex-acp")
		if err != nil {
			t.Skip("install the pinned codex-acp adapter or set CODEX_ACP_TEST_BIN to run the real authentication smoke test")
		}
	}
	adapter, err := filepath.Abs(adapter)
	if err != nil {
		t.Fatal(err)
	}
	// Both shipped Codex profiles (API key, ChatGPT subscription) run codex-acp.
	for _, file := range []string{"environment-codex-acp.yaml", "environment-codex-chatgpt.yaml"} {
		t.Run(file, func(t *testing.T) { codexExampleSession(t, adapter, file) })
	}
}

func codexExampleSession(t *testing.T, adapter, file string) {
	isolate := noNetwork(t)
	raw, err := os.ReadFile("../../examples/catalog/" + file)
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
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, isolate[0], append(isolate[1:], adapter)...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.Dir = home
	// Deliberately exclude the developer's auth, provider overrides, and default
	// auth request. Only the shipped profile may supply those settings.
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "CODEX_HOME=" + home, "NO_COLOR=1"}
	for name, value := range profile.Env {
		cmd.Env = append(cmd.Env, name+"="+value)
	}
	if binary := os.Getenv("CODEX_ACP_TEST_CODEX_PATH"); binary != "" {
		cmd.Env = append(cmd.Env, "CODEX_PATH="+binary)
	}
	if _, err := writeHarnessFiles(mustMarshalHarnessFiles(t, profile.Harness.Files), home); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.WaitDelay = time.Second
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = stdin.Close()
		// Kill the group before reaping its leader, even if the adapter already
		// exited: app-server children must not outlive this test.
		_ = cmd.Cancel()
		_ = cmd.Wait()
		if t.Failed() {
			t.Logf("adapter stderr:\n%s", stderr.String())
		}
	}()
	// The runner's wiring: the wire carries the system prompt.
	wire := newACPWire(stdin, stdout)
	conn := acp.NewClientSideConnection(&acpClient{emit: func(string) {}}, wire, wire)
	if _, err := conn.Initialize(ctx, acp.InitializeRequest{ProtocolVersion: acp.ProtocolVersionNumber}); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	// codex-acp declares the client system prompt: the instructions go as Codex's
	// developer_instructions, and a malformed field would refuse the session.
	if !wire.SystemPrompt() {
		t.Fatal("codex-acp does not declare sessionCapabilities.systemPrompt")
	}
	session, err := conn.NewSession(ctx, acp.NewSessionRequest{Cwd: home, McpServers: []acp.McpServer{}, Meta: sessionMeta("Answer in one word.")})
	if err != nil {
		t.Fatalf("the shipped Codex ACP profile cannot create a session in a clean HOME: %v", err)
	}
	if session.SessionId == "" {
		t.Fatal("session/new returned an empty session id")
	}
	// The profile's mode is one codex-acp offers and accepts.
	var notices []string
	configureACPSession(ctx, conn, session.SessionId, acpSessionState{modes: session.Modes, options: session.ConfigOptions},
		profile.Harness.Mode, "", func(f string, a ...any) { notices = append(notices, fmt.Sprintf(f, a...)) })
	if profile.Harness.Mode == "" || len(notices) != 0 {
		t.Fatalf("mode %q: %q", profile.Harness.Mode, notices)
	}
}

func mustMarshalHarnessFiles(t *testing.T, files map[string]string) string {
	t.Helper()
	if len(files) == 0 {
		return ""
	}
	b, err := json.Marshal(files)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
