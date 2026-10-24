package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"agent-sandbox/internal/drift"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/plan"
)

func TestMarkdownRenderersForPullRequests(t *testing.T) {
	p := plan.Plan{Valid: true, Bundle: "b1", Fingerprint: "f1", Summary: plan.Summary{Create: 1, Update: 1, Noop: 1}, Changes: []plan.Change{
		{Kind: model.KindEnvironment, Tenant: "acme", Name: "py", Action: plan.ActionCreate, NextRevision: 1},
		{Kind: model.KindAgent, Tenant: "acme", Name: "backend", Action: plan.ActionUpdate, CurrentRevision: 2, NextRevision: 3,
			Diff: []plan.FieldChange{{Path: "spec.repo", From: "a", To: "b|c"}}},
		{Kind: model.KindConnection, Tenant: "", Name: "gh", Action: plan.ActionNoop, CurrentRevision: 1, NextRevision: 1},
	}}
	var buf bytes.Buffer
	markdownPlan(&buf, p, "bundles/acme.yaml")
	out := buf.String()
	for _, want := range []string{Marker, "### Plan ✅ valid · `bundles/acme.yaml`", "1 to create, 1 to update, 1 unchanged, 0 invalid", "plan `f1`",
		"| ➕ create | EnvironmentProfile | acme | `py` | 0 → 1 |", "| ✏️ update | AgentDefinition | acme | `backend` | 2 → 3 | `spec.repo: a -> b|c` |",
		"| · noop | Connection | - | `gh` | 1 | - |", "Merging applies exactly these changes"} {
		if !strings.Contains(out, want) {
			t.Errorf("plan markdown lacks %q:\n%s", want, out)
		}
	}
	if !strings.HasPrefix(out, Marker+"\n") {
		t.Fatal("the marker must open the block so a pipeline can update its own comment")
	}
	// Invalid: the verdict, the per-document error (pipes escaped) and the bundle-level error.
	bad := plan.Plan{Valid: false, Summary: plan.Summary{Invalid: 1}, Errors: []string{"documents 1 and 2 both describe X"},
		Changes: []plan.Change{{Kind: model.KindAgent, Tenant: "acme", Name: "x", Action: plan.ActionInvalid, Errors: []string{"may not use policy a|b"}}}}
	buf.Reset()
	markdownPlan(&buf, bad, "")
	out = buf.String()
	if !strings.Contains(out, "### Plan ❌ invalid\n") || !strings.Contains(out, "- ❌ bundle: documents 1 and 2 both describe X") ||
		!strings.Contains(out, "| ❌ invalid | AgentDefinition | acme | `x` | 0 | ❌ may not use policy a\\|b |") || !strings.Contains(out, "would be refused") {
		t.Errorf("invalid plan markdown:\n%s", out)
	}
	// Nothing to do.
	buf.Reset()
	markdownPlan(&buf, plan.Plan{Valid: true}, "")
	if !strings.Contains(buf.String(), "Nothing would change") {
		t.Errorf("noop plan markdown:\n%s", buf.String())
	}

	a := model.Apply{ID: "apply_1", Status: model.ApplyFailed, Error: "step 2 (AgentDefinition acme/backend): boom",
		Source: &model.Source{Commit: "0123456789abcdef0123456789abcdef01234567", Repo: "https://github.com/acme/platform.git", Path: "bundles/acme.yaml"},
		Steps: []model.ApplyStep{
			{Kind: model.KindEnvironment, Tenant: "acme", Name: "py", Action: plan.ActionCreate, Status: model.StepDone, Revision: 1},
			{Kind: model.KindAgent, Tenant: "acme", Name: "backend", Action: plan.ActionCreate, Status: model.StepFailed, Error: "boom"},
		}}
	buf.Reset()
	markdownApply(&buf, a)
	out = buf.String()
	for _, want := range []string{"### Apply ❌ failed · `apply_1`", "step 2 (AgentDefinition acme/backend): boom", "Source: `0123456789abcdef0123456789abcdef01234567` in https://github.com/acme/platform.git (`bundles/acme.yaml`)",
		"| 1 | EnvironmentProfile | acme | `py` | ➕ create | done | 1 | - |", "| 2 | AgentDefinition | acme | `backend` | ➕ create | failed | - | boom |", "sandboxctl apply -resume apply_1"} {
		if !strings.Contains(out, want) {
			t.Errorf("apply markdown lacks %q:\n%s", want, out)
		}
	}
	buf.Reset()
	markdownApply(&buf, model.Apply{ID: "apply_2", Status: model.ApplyDone})
	if strings.Contains(buf.String(), "-resume") || !strings.Contains(buf.String(), "### Apply ✅ done") {
		t.Errorf("done apply markdown:\n%s", buf.String())
	}

	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	rep := drift.Report{Tenant: "acme", Checked: 3, At: now, Drifted: []drift.Entry{
		{Kind: model.KindEnvironment, Tenant: "acme", Name: "py", State: drift.Changed,
			Applied: drift.Revision{Revision: 1, Source: &model.Source{Apply: "apply_1", Commit: "0123456789abcdef"}},
			Current: &drift.Revision{Revision: 2, CreatedBy: "mallory"}, Diff: []plan.FieldChange{{Path: "spec.image", From: "stable", To: "canary"}}},
		{Kind: model.KindConnection, Tenant: "acme", Name: "gh", State: drift.Deleted, Applied: drift.Revision{Revision: 1, Source: &model.Source{Apply: "apply_1"}}},
	}}
	buf.Reset()
	markdownDrift(&buf, rep)
	out = buf.String()
	for _, want := range []string{"### Drift ⚠️ 2 of 3 managed items", "| changed | EnvironmentProfile | acme | `py` | 1 (`apply_1` @ `0123456789ab`) | 2 | mallory | `spec.image: stable -> canary` |",
		"| deleted | Connection | acme | `gh` | 1 (`apply_1`) | - | - | - |", "sandboxctl rollback"} {
		if !strings.Contains(out, want) {
			t.Errorf("drift markdown lacks %q:\n%s", want, out)
		}
	}
	buf.Reset()
	markdownDrift(&buf, drift.Report{Checked: 3})
	if !strings.Contains(buf.String(), "### Drift ✅ none · 3 managed items") {
		t.Errorf("clean drift markdown:\n%s", buf.String())
	}
}
