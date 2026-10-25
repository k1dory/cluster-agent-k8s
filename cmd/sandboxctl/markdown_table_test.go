package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"agent-sandbox/internal/drift"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/plan"
)

// tableRows checks every table in a rendered block: each row has as many cells as its header,
// counting only the pipes that are not escaped, and no row spans two lines.
func tableRows(t *testing.T, out string) int {
	t.Helper()
	cells := func(line string) int {
		return strings.Count(strings.ReplaceAll(line, "\\|", ""), "|")
	}
	rows, header := 0, 0
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "|") {
			header = 0
			continue
		}
		if header == 0 {
			header = cells(line)
			continue
		}
		if got := cells(line); got != header {
			t.Errorf("row has %d pipes, header %d: %q", got, header, line)
		}
		if !strings.HasPrefix(line, "|---") {
			rows++
		}
	}
	return rows
}

func TestMarkdownTablesSurviveMultiLineValuesAndPipes(t *testing.T) {
	// A value with a pipe and a line break inside a code span, and a name with both: the row
	// stays one row with the header's cells. Backticks cannot end the span either.
	p := plan.Plan{Valid: true, Summary: plan.Summary{Update: 1, Create: 1}, Changes: []plan.Change{
		{Kind: model.KindConnection, Tenant: "acme", Name: "tools", Action: plan.ActionUpdate, CurrentRevision: 1, NextRevision: 2,
			Diff: []plan.FieldChange{{Path: "spec.headers.X-Note", From: "a|b", To: "line one\nline two | three\r\n`four`"}}},
		{Kind: model.KindAgent, Tenant: "acme", Name: "odd|name\nwith break", Action: plan.ActionCreate, NextRevision: 1},
		{Kind: model.KindAgent, Tenant: "acme", Name: "bad", Action: plan.ActionInvalid, Errors: []string{"first line\nsecond | line"}},
	}}
	var buf bytes.Buffer
	markdownPlan(&buf, p, "bundles/a|b.yaml")
	out := buf.String()
	if rows := tableRows(t, out); rows != 3 {
		t.Errorf("plan table: %d rows, want 3:\n%s", rows, out)
	}
	for _, want := range []string{"`bundles/a\\|b.yaml`", "`odd\\|name with break`", "line one line two \\| three 'four'", "❌ first line second \\| line"} {
		if !strings.Contains(out, want) {
			t.Errorf("plan markdown lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\r") {
		t.Error("a carriage return survived into the comment")
	}

	a := model.Apply{ID: "apply_1", Status: model.ApplyFailed, Error: "step 2: first\nsecond | third",
		Source: &model.Source{Commit: "0123456789abcdef0123456789abcdef01234567", Repo: "https://example.com/acme/platform.git", Path: "bundles/x|y.yaml"},
		Steps: []model.ApplyStep{
			{Kind: model.KindEnvironment, Tenant: "acme", Name: "py", Action: plan.ActionCreate, Status: model.StepDone, Revision: 1},
			{Kind: model.KindAgent, Tenant: "acme", Name: "back|end", Action: plan.ActionCreate, Status: model.StepFailed, Error: "refused:\n  policy a|b"},
		}}
	buf.Reset()
	markdownApply(&buf, a)
	out = buf.String()
	if rows := tableRows(t, out); rows != 2 {
		t.Errorf("apply table: %d rows, want 2:\n%s", rows, out)
	}
	for _, want := range []string{"step 2: first second \\| third", "(`bundles/x\\|y.yaml`)", "| `back\\|end` |", "| refused:   policy a\\|b |"} {
		if !strings.Contains(out, want) {
			t.Errorf("apply markdown lacks %q:\n%s", want, out)
		}
	}

	rep := drift.Report{Checked: 2, Drifted: []drift.Entry{{Kind: model.KindEnvironment, Tenant: "acme", Name: "py", State: drift.Changed,
		Applied: drift.Revision{Revision: 1, Source: &model.Source{Apply: "apply_1", Commit: "0123456789abcdef"}},
		Current: &drift.Revision{Revision: 2, CreatedBy: "key:abc|def"}, Diff: []plan.FieldChange{{Path: "spec.env.NOTE", From: "x", To: "one\ntwo|three"}}}}}
	buf.Reset()
	markdownDrift(&buf, rep)
	out = buf.String()
	if rows := tableRows(t, out); rows != 1 {
		t.Errorf("drift table: %d rows, want 1:\n%s", rows, out)
	}
	if !strings.Contains(out, "| key:abc\\|def |") || !strings.Contains(out, "`spec.env.NOTE: x -> one two\\|three`") {
		t.Errorf("drift markdown:\n%s", out)
	}
}

func TestMarkdownFailureBlockCarriesTheMarker(t *testing.T) {
	var buf bytes.Buffer
	markdownFailure(&buf, "Apply", "bundles/acme.yaml", errors.New("POST /v1/plan: 503 Service Unavailable: store unavailable\nretry | later"))
	out := buf.String()
	if !strings.HasPrefix(out, Marker+"\n### Apply ❌ error · `bundles/acme.yaml`\n\n") {
		t.Fatalf("failure block must open with the marker and the verdict:\n%s", out)
	}
	if !strings.Contains(out, "store unavailable retry \\| later") || !strings.Contains(out, "produced no result") {
		t.Errorf("failure block:\n%s", out)
	}
	buf.Reset()
	markdownFailure(&buf, "Drift", "", errors.New("GET /v1/drift: 401 Unauthorized"))
	if !strings.HasPrefix(buf.String(), Marker+"\n### Drift ❌ error\n\n") {
		t.Errorf("failure block without a file:\n%s", buf.String())
	}
}
