package main

import (
	"io"

	"agent-sandbox/internal/drift"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/plan"
	"agent-sandbox/internal/render"
)

// The Markdown renderers live in internal/render, shared with the platform's webhook handler
// (a pull request comment reads the same whoever posted it); these names keep the CLI's call
// sites and tests.

// Marker opens every rendered block.
const Marker = render.Marker

func markdownPlan(w io.Writer, p plan.Plan, file string) { render.Plan(w, p, file) }
func markdownApply(w io.Writer, a model.Apply)           { render.Apply(w, a) }
func markdownDrift(w io.Writer, rep drift.Report)        { render.Drift(w, rep) }
func markdownFailure(w io.Writer, what, file string, err error) {
	render.Failure(w, what, file, err)
}
func mdCode(s string) string   { return render.Code(s) }
func mdCell(s string) string   { return render.Cell(s) }
func mdEscape(s string) string { return render.Escape(s) }
