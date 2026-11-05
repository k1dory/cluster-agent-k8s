package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	acp "github.com/coder/acp-go-sdk"

	"agent-sandbox/internal/catalog"
)

// This smoke test needs the real adapter, not a mock of its authentication
// behavior. It runs automatically when codex-acp is on PATH (e.g. in the agent
// image), or with CODEX_ACP_TEST_BIN=/absolute/path/to/codex-acp. An optional
// CODEX_ACP_TEST_CODEX_PATH selects the exact Codex binary under test.
// No prompt is sent and no real API key or existing login is used.
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
	raw, err := os.ReadFile("../../examples/catalog/environment-codex-acp.yaml")
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
	cmd := exec.CommandContext(ctx, adapter)
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
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			cancel()
			<-done
		}
		if t.Failed() {
			t.Logf("adapter stderr:\n%s", stderr.String())
		}
	}()
	conn := acp.NewClientSideConnection(&acpClient{emit: func(string) {}}, stdin, stdout)
	if _, err := conn.Initialize(ctx, acp.InitializeRequest{ProtocolVersion: acp.ProtocolVersionNumber}); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	session, err := conn.NewSession(ctx, acp.NewSessionRequest{Cwd: home, McpServers: []acp.McpServer{}})
	if err != nil {
		t.Fatalf("the shipped Codex ACP profile cannot create a session in a clean HOME: %v", err)
	}
	if session.SessionId == "" {
		t.Fatal("session/new returned an empty session id")
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
