package catalog

import (
	"context"
	"errors"
	"os"
	"testing"

	"agent-sandbox/internal/model"
)

// An ACP profile names the agent program and, optionally, how its permission requests are
// answered; both reach the launch. permissions means nothing outside acp and is refused there.
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
	} {
		if _, err := s.Put(ctx, model.KindEnvironment, "acme", doc(t, "acp", bad, nil), false, "alice"); !errors.Is(err, ErrInvalid) {
			t.Errorf("must be invalid: %s → %v", bad, err)
		}
	}
	spec := `{"image":"stable","harness":{"command":"codex-acp","input":"acp","permissions":"deny","auth_method":"api-key"}}`
	if _, err := s.Put(ctx, model.KindEnvironment, "acme", doc(t, "acp", spec, nil), false, "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(ctx, model.KindAgent, "acme", doc(t, "coder", `{"policy":"backend-dev","environment":"acp"}`, nil), false, "alice"); err != nil {
		t.Fatal(err)
	}
	r, err := s.Resolve(ctx, "acme", "coder", false)
	if err != nil || r.Launch.HarnessCommand != "codex-acp" || r.Launch.HarnessInput != "acp" || r.Launch.HarnessPermissions != "deny" || r.Launch.HarnessAuthMethod != "api-key" {
		t.Fatalf("resolve: %v %+v", err, r.Launch)
	}
}

// The shipped ACP profiles apply as they are.
func TestShippedACPProfiles(t *testing.T) {
	s := newService()
	for _, f := range []string{"../../examples/catalog/environment-claude-acp.yaml", "../../examples/catalog/environment-codex-acp.yaml",
		"../../examples/catalog/environment-opencode-acp.yaml"} {
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
