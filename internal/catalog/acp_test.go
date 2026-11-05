package catalog

import (
	"context"
	"errors"
	"os"
	"testing"

	"agent-sandbox/internal/model"
)

// An ACP profile names the agent program and, optionally, how its permission requests are
// answered, its session mode and when it gets MCP servers; all reach the launch. These mean
// nothing outside acp and are refused there.
func TestACPProfileValidationAndLaunch(t *testing.T) {
	s := newService()
	ctx := context.Background()
	for _, bad := range []string{
		`{"image":"stable","harness":{"input":"jsonrpc"}}`,
		`{"image":"stable","harness":{"command":"claude-agent-acp","input":"acp","permissions":"ask"}}`,
		`{"image":"stable","harness":{"permissions":"deny"}}`,
		`{"image":"stable","harness":{"input":"stream-json","permissions":"allow"}}`,
		`{"image":"stable","harness":{"auth_method":"api-key"}}`,
		`{"image":"stable","harness":{"command":"codex-acp","input":"acp","auth_method":"api key"}}`,
		`{"image":"stable","harness":{"mode":"build"}}`,
		`{"image":"stable","harness":{"command":"codex-acp","input":"acp","mode":"full access"}}`,
		`{"image":"stable","harness":{"command":"hermes acp","input":"acp","mcp":"never"}}`,
		`{"image":"stable","harness":{"input":"text","mcp":"always"}}`,
	} {
		if _, err := s.Put(ctx, model.KindEnvironment, "acme", doc(t, "acp", bad, nil), false, "alice"); !errors.Is(err, ErrInvalid) {
			t.Errorf("must be invalid: %s → %v", bad, err)
		}
	}
	spec := `{"image":"stable","harness":{"command":"codex-acp","input":"acp","permissions":"deny","auth_method":"api-key","mode":"agent-full-access","mcp":"always"}}`
	if _, err := s.Put(ctx, model.KindEnvironment, "acme", doc(t, "acp", spec, nil), false, "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(ctx, model.KindAgent, "acme", doc(t, "coder", `{"policy":"backend-dev","environment":"acp"}`, nil), false, "alice"); err != nil {
		t.Fatal(err)
	}
	r, err := s.Resolve(ctx, "acme", "coder", false)
	if err != nil || r.Launch.HarnessCommand != "codex-acp" || r.Launch.HarnessInput != "acp" || r.Launch.HarnessPermissions != "deny" || r.Launch.HarnessAuthMethod != "api-key" ||
		r.Launch.HarnessMode != "agent-full-access" || r.Launch.HarnessMCP != "always" {
		t.Fatalf("resolve: %v %+v", err, r.Launch)
	}
}

// The shipped ACP profiles apply as they are.
func TestShippedACPProfiles(t *testing.T) {
	s := newService()
	for _, f := range []string{"../../examples/catalog/environment-claude-acp.yaml", "../../examples/catalog/environment-codex-acp.yaml",
		"../../examples/catalog/environment-opencode-acp.yaml", "../../examples/catalog/environment-hermes-acp.yaml"} {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		d, err := ParseYAML(raw)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if _, err := s.Put(context.Background(), d.Kind, "acme", d, false, "ci"); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
	}
}
