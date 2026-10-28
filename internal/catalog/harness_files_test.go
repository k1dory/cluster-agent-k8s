package catalog

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"agent-sandbox/internal/model"
)

// A profile's harness files are relative paths inside the home directory, in their clean
// form, within the limits; they reach the sandbox's launch as they were written.
func TestHarnessFilesValidationAndLaunch(t *testing.T) {
	s := newService()
	ctx := context.Background()
	big := strings.Repeat("x", MaxHarnessFilesSize)
	many := map[string]string{}
	for i := 0; i <= MaxHarnessFiles; i++ {
		many[fmt.Sprintf("f%d", i)] = ""
	}
	manyJSON := `{`
	for k := range many {
		manyJSON += `"` + k + `":"",`
	}
	manyJSON = strings.TrimSuffix(manyJSON, ",") + `}`
	for _, bad := range []string{
		`{"/etc/passwd":"x"}`,
		`{"../x":"x"}`,
		`{"a/../../x":"x"}`,
		`{"a/../b":"x"}`, // not clean: spelled as it resolves, or not at all
		`{"./a":"x"}`,
		`{"":"x"}`,
		`{".":"x"}`,
		`{"a\\b":"x"}`,
		`{"a":"` + big + `"}`,
		manyJSON,
	} {
		spec := `{"image":"stable","harness":{"files":` + bad + `}}`
		if _, err := s.Put(ctx, model.KindEnvironment, "acme", doc(t, "files", spec, nil), false, "alice"); !errors.Is(err, ErrInvalid) {
			t.Errorf("must be invalid: %.80s → %v", bad, err)
		}
	}
	spec := `{"image":"stable","harness":{"command":"codex exec \"$SANDBOX_TASK\"","files":{".codex/config.toml":"model_provider = \"gateway\"\n"}}}`
	if _, err := s.Put(ctx, model.KindEnvironment, "acme", doc(t, "codex", spec, nil), false, "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(ctx, model.KindAgent, "acme", doc(t, "coder", `{"policy":"backend-dev","environment":"codex"}`, nil), false, "alice"); err != nil {
		t.Fatal(err)
	}
	r, err := s.Resolve(ctx, "acme", "coder", false)
	if err != nil || r.Launch.HarnessFiles[".codex/config.toml"] != "model_provider = \"gateway\"\n" || len(r.Launch.HarnessFiles) != 1 {
		t.Fatalf("resolve: %v %+v", err, r)
	}
}

// The subscription profile applies as shipped and keeps its placeholder out of the API-key
// variable: Claude Code must speak the OAuth dialect for the gateway's swap to work.
func TestShippedSubscriptionProfile(t *testing.T) {
	s := newService()
	raw, err := os.ReadFile("../../examples/catalog/environment-claude-subscription.yaml")
	if err != nil {
		t.Fatal(err)
	}
	d, err := ParseYAML(raw)
	if err != nil {
		t.Fatal(err)
	}
	it, err := s.Put(context.Background(), d.Kind, "acme", d, false, "ci")
	if err != nil {
		t.Fatal(err)
	}
	spec := string(it.Spec)
	if !strings.Contains(spec, `"CLAUDE_CODE_OAUTH_TOKEN":"sk-ant-oat01-placeholder`) || strings.Contains(spec, "ANTHROPIC_API_KEY") {
		t.Fatalf("the profile must carry a placeholder OAuth token and no API key: %s", spec)
	}
}
