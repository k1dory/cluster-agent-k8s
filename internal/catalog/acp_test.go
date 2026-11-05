package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
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
		`{"image":"stable","harness":{"thought_level":"high"}}`,
		`{"image":"stable","harness":{"command":"codex-acp","input":"acp","thought_level":"very high"}}`,
		`{"image":"stable","harness":{"session_meta":{"a":1}}}`,
		`{"image":"stable","harness":{"command":"x","input":"acp","session_meta":{"pad":"` + strings.Repeat("x", 17<<10) + `"}}}`,
		`{"image":"stable","harness":{"instructions":"file"}}`,
		`{"image":"stable","harness":{"command":"x","input":"acp","instructions":"prompt"}}`,
		`{"image":"stable","harness":{"command":"x","input":"acp","instructions":"env:SANDBOX_INSTRUCTIONS"}}`,
		`{"image":"stable","harness":{"command":"x","input":"acp","instructions":"env:HARNESS_CMD"}}`,
		`{"image":"stable","harness":{"command":"x","input":"acp","instructions":"env:1BAD"}}`,
	} {
		if _, err := s.Put(ctx, model.KindEnvironment, "acme", doc(t, "acp", bad, nil), false, "alice"); !errors.Is(err, ErrInvalid) {
			t.Errorf("must be invalid: %s → %v", bad, err)
		}
	}
	spec := `{"image":"stable","harness":{"command":"codex-acp","input":"acp","permissions":"deny","auth_method":"api-key","mode":"agent-full-access","mcp":"always","thought_level":"high","session_meta":{"claudeCode":{"options":{"maxTurns":40}}},"instructions":"env:HERMES_ENVIRONMENT_HINT"}}`
	if _, err := s.Put(ctx, model.KindEnvironment, "acme", doc(t, "acp", spec, nil), false, "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(ctx, model.KindAgent, "acme", doc(t, "coder", `{"policy":"backend-dev","environment":"acp"}`, nil), false, "alice"); err != nil {
		t.Fatal(err)
	}
	r, err := s.Resolve(ctx, "acme", "coder", false)
	if err != nil || r.Launch.HarnessCommand != "codex-acp" || r.Launch.HarnessInput != "acp" || r.Launch.HarnessPermissions != "deny" || r.Launch.HarnessAuthMethod != "api-key" ||
		r.Launch.HarnessMode != "agent-full-access" || r.Launch.HarnessMCP != "always" || r.Launch.HarnessThoughtLevel != "high" ||
		r.Launch.HarnessSessionMeta != `{"claudeCode":{"options":{"maxTurns":40}}}` || r.Launch.HarnessInstructions != "env:HERMES_ENVIRONMENT_HINT" {
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

// Every shipped profile runs its agent over ACP: `claude -p` in a pod refuses every edit nobody
// approves, `codex exec` keeps no conversation open and records no approvals; only ACP brings the
// requests to the runner. text and stream-json are a documented fallback.
func TestShippedProfilesUseACP(t *testing.T) {
	files, err := filepath.Glob("../../examples/catalog/*.yaml")
	if err != nil || len(files) == 0 {
		t.Fatal(files, err)
	}
	s := newService()
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		docs, err := ParseYAMLAll(raw)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		for _, d := range docs {
			if d.Kind != model.KindEnvironment {
				continue
			}
			var spec EnvironmentSpec
			if err := json.Unmarshal(d.Spec, &spec); err != nil {
				t.Fatal(err)
			}
			cmd := spec.Harness.Command
			if strings.Contains(cmd, "claude -p") || strings.HasPrefix(cmd, "claude ") || strings.Contains(cmd, "codex exec") {
				t.Errorf("%s (%s): agents run over ACP (claude-agent-acp, codex-acp), not %q", f, d.Name, cmd)
			}
			if cmd != "" && (spec.Harness.Input != "acp" || spec.Harness.ResumeCommand != "") {
				t.Errorf("%s (%s): a shipped harness is ACP (input acp, no resume command): %+v", f, d.Name, spec.Harness)
			}
			if _, err := s.Put(context.Background(), d.Kind, "acme", d, false, "ci"); err != nil {
				t.Errorf("%s (%s): %v", f, d.Name, err)
			}
		}
	}
}
