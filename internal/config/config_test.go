package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The chart renders api_keys.max_ttl as a quoted string ("0", "720h"); both must load as a
// duration, and the example configuration must load at all.
func TestAPIKeysMaxTTLParsesQuotedDurations(t *testing.T) {
	dir := t.TempDir()
	for raw, want := range map[string]time.Duration{`"0"`: 0, `"720h"`: 720 * time.Hour, `30m`: 30 * time.Minute} {
		path := filepath.Join(dir, "c.yaml")
		if err := os.WriteFile(path, []byte("api_token: x\nruntime: fake\napi_keys:\n  max_ttl: "+raw+"\npolicies_dir: policies\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		c, err := Load(path)
		if err != nil || c.APIKeys.MaxTTL != want {
			t.Fatalf("max_ttl %s: %v %v", raw, err, c)
		}
	}
	if _, err := Load("../../config/sandboxd.example.yaml"); err != nil {
		t.Fatalf("example config: %v", err)
	}
}

// The harness commands name the agent's variables ($SANDBOX_TASK, ${SANDBOX_SESSION}, …): they
// reach the agent as written, while sandboxd's own ${VARS} are still expanded. Expanding them
// at load gave every pod `claude -p ""` (seen on a live cluster).
func TestHarnessCommandsKeepTheAgentsVariables(t *testing.T) {
	t.Setenv("SANDBOX_TASK", "sandboxd must not use this")
	t.Setenv("GATEWAY_FIXTURE", "10.0.0.1")
	path := filepath.Join(t.TempDir(), "c.yaml")
	body := "api_token: x\nruntime: fake\npolicies_dir: policies\ngateway:\n  ip: ${GATEWAY_FIXTURE}\n" +
		"kube:\n  harness_command: 'claude -p \"$SANDBOX_TASK\" --mcp-config \"${SANDBOX_MCP_CONFIG}\"'\n" +
		"  harness_resume_command: 'claude -p \"$SANDBOX_RESUME_PROMPT\" --resume \"$SANDBOX_SESSION\"'\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := `claude -p "${SANDBOX_TASK}" --mcp-config "${SANDBOX_MCP_CONFIG}"`; c.Kube.HarnessCommand != want {
		t.Fatalf("harness_command = %q, want %q", c.Kube.HarnessCommand, want)
	}
	if want := `claude -p "${SANDBOX_RESUME_PROMPT}" --resume "${SANDBOX_SESSION}"`; c.Kube.HarnessResumeCommand != want {
		t.Fatalf("harness_resume_command = %q, want %q", c.Kube.HarnessResumeCommand, want)
	}
	if c.Gateway.IP != "10.0.0.1" {
		t.Fatalf("sandboxd's own variables must still expand: gateway.ip = %q", c.Gateway.IP)
	}
}
