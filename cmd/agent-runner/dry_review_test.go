package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The runner's client and the gateway bridge read the identity the same way, and refuse a
// gateway CA file that holds no certificate instead of trusting nothing.
func TestLoadIdentityRefusesAnEmptyTrust(t *testing.T) {
	if _, _, err := loadIdentity(t.TempDir()); err == nil || !strings.Contains(err.Error(), "client cert") {
		t.Fatalf("no certificate: %v", err)
	}
	dir := newTestGateway(t, http.NotFoundHandler()).certDir
	if _, pool, err := loadIdentity(dir); err != nil || pool == nil {
		t.Fatalf("identity: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "gateway-ca.crt"), []byte("not a certificate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadIdentity(dir); err == nil || !strings.Contains(err.Error(), "holds no certificate") {
		t.Fatalf("garbage CA: %v", err)
	}
	if _, err := newGatewayBridge(dir); err == nil {
		t.Fatal("the bridge accepted a CA file without a certificate")
	}
}

// One MCP decoder for the Claude config and the ACP session; a rollout's resume prompt is the
// one execute put in the run's environment.
func TestSharedHarnessHelpers(t *testing.T) {
	list, err := parseMCPServers(`[{"name":"a","url":"https://a.example/mcp"},{"name":"","url":"x"},{"name":"b"}]`)
	if err != nil || len(list) != 1 || list[0].Name != "a" {
		t.Fatalf("servers: %v %+v", err, list)
	}
	if _, err := parseMCPServers("{"); err == nil {
		t.Fatal("malformed servers accepted")
	}
	if s, skipped := acpMCPServers("{", true); len(s) != 0 || skipped != 0 {
		t.Fatalf("acp servers from malformed input: %v %d", s, skipped)
	}
	env := []string{"SANDBOX_RESUME_PROMPT=old", "OTHER=1", "SANDBOX_RESUME_PROMPT=" + defaultResumePrompt}
	if got := envValue(env, "SANDBOX_RESUME_PROMPT"); got != defaultResumePrompt {
		t.Fatalf("resume prompt %q", got)
	}
	root := t.TempDir()
	t.Setenv("PWD", root)
	t.Setenv("SANDBOX_REPO_DIR", filepath.Join(root, "repo"))
	if harnessDir() != root {
		t.Fatalf("without a checkout: %s", harnessDir())
	}
	if err := os.MkdirAll(filepath.Join(root, "repo", ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if harnessDir() != filepath.Join(root, "repo") {
		t.Fatalf("with a checkout: %s", harnessDir())
	}
}
