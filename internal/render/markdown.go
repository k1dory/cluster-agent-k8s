// Package render turns plans, applies and drift reports into Markdown for the Git adapters:
// a plan as the comment on a pull request, an apply as the job summary of the merge, a drift
// report as the body of an alert. Each block starts with a marker line so a pipeline (or the
// platform's own webhook handler) can find and update its own comment instead of adding one
// per push. The CLI and the webhook handler share these, so a comment reads the same whoever
// posted it.
package render

import (
	"fmt"
	"io"
	"strings"

	"agent-sandbox/internal/drift"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/plan"
)

// Marker opens every rendered block (an HTML comment: invisible on GitHub and GitLab).
const Marker = "<!-- agent-sandbox -->"

func Plan(w io.Writer, p plan.Plan, file string) {
	fmt.Fprintln(w, Marker)
	verdict := "✅ valid"
	if !p.Valid {
		verdict = "❌ invalid"
	}
	fmt.Fprintf(w, "### Plan %s", verdict)
	if file != "" {
		fmt.Fprintf(w, " · %s", Code(file))
	}
	fmt.Fprintf(w, "\n\n%d to create, %d to update, %d unchanged, %d invalid · bundle `%s` · plan `%s`\n\n",
		p.Summary.Create, p.Summary.Update, p.Summary.Noop, p.Summary.Invalid, p.Bundle, p.Fingerprint)
	for _, e := range p.Errors {
		fmt.Fprintf(w, "- ❌ bundle: %s\n", Escape(e))
	}
	if len(p.Errors) > 0 {
		fmt.Fprintln(w)
	}
	fmt.Fprintln(w, "| Action | Kind | Tenant | Name | Revision | Changes |")
	fmt.Fprintln(w, "|---|---|---|---|---|---|")
	for _, c := range p.Changes {
		detail := "-"
		switch {
		case len(c.Errors) > 0:
			detail = "❌ " + Escape(strings.Join(c.Errors, "; "))
		case c.Action == plan.ActionNoop:
		default:
			detail = Code(FormatDiff(c.Diff))
		}
		rev := fmt.Sprintf("%d → %d", c.CurrentRevision, c.NextRevision)
		if c.Action == plan.ActionNoop || c.Action == plan.ActionInvalid {
			rev = fmt.Sprint(c.CurrentRevision)
		}
		fmt.Fprintf(w, "| %s | %s | %s | %s | %s | %s |\n", ActionIcon(c.Action), c.Kind, Cell(c.Tenant), Code(c.Name), rev, detail)
	}
	if !p.Valid {
		fmt.Fprintln(w, "\nThe bundle is not valid: `apply` on merge would be refused. Fix the documents above before merging.")
	} else if p.Summary.Create+p.Summary.Update == 0 {
		fmt.Fprintln(w, "\nNothing would change: the platform already holds this bundle.")
	} else {
		fmt.Fprintln(w, "\nMerging applies exactly these changes (one transaction per step, continued by key), with this commit as the source of every new revision.")
	}
}

func Apply(w io.Writer, a model.Apply) {
	fmt.Fprintln(w, Marker)
	icon := map[string]string{model.ApplyDone: "✅", model.ApplyFailed: "❌", model.ApplyConflict: "⚠️", model.ApplyRunning: "⏳"}[a.Status]
	fmt.Fprintf(w, "### Apply %s %s · %s\n\n", icon, a.Status, Code(a.ID))
	if a.Error != "" {
		fmt.Fprintf(w, "%s\n\n", Escape(a.Error))
	}
	if a.Source != nil && a.Source.Commit != "" {
		fmt.Fprintf(w, "Source: %s", Code(a.Source.Commit))
		if a.Source.Repo != "" {
			fmt.Fprintf(w, " in %s", Escape(a.Source.Repo))
		}
		if a.Source.Path != "" {
			fmt.Fprintf(w, " (%s)", Code(a.Source.Path))
		}
		fmt.Fprint(w, "\n\n")
	}
	fmt.Fprintln(w, "| Step | Kind | Tenant | Name | Action | Status | Revision | Error |")
	fmt.Fprintln(w, "|---|---|---|---|---|---|---|---|")
	for i, st := range a.Steps {
		rev := "-"
		if st.Revision > 0 {
			rev = fmt.Sprint(st.Revision)
		}
		fmt.Fprintf(w, "| %d | %s | %s | %s | %s | %s | %s | %s |\n", i+1, st.Kind, Cell(st.Tenant), Code(st.Name), ActionIcon(st.Action), st.Status, rev, Cell(st.Error))
	}
	if a.Status != model.ApplyDone {
		fmt.Fprintf(w, "\nContinue with %s once the cause is fixed (the same bundle under the same key continues it too); the applied steps stay as they are.\n", Code("sandboxctl apply -resume "+a.ID))
	}
}

func Drift(w io.Writer, rep drift.Report) {
	fmt.Fprintln(w, Marker)
	if len(rep.Drifted) == 0 {
		fmt.Fprintf(w, "### Drift ✅ none · %d managed items\n", rep.Checked)
		return
	}
	fmt.Fprintf(w, "### Drift ⚠️ %d of %d managed items\n\n", len(rep.Drifted), rep.Checked)
	fmt.Fprintln(w, "| State | Kind | Tenant | Name | Applied | Current | By | Changes |")
	fmt.Fprintln(w, "|---|---|---|---|---|---|---|---|")
	for _, e := range rep.Drifted {
		applied := fmt.Sprintf("%d (%s", e.Applied.Revision, Code(e.Applied.Source.Apply))
		if e.Applied.Source.Commit != "" {
			applied += " @ " + Code(ShortSHA(e.Applied.Source.Commit))
		}
		applied += ")"
		current, by := "-", "-"
		if e.Current != nil {
			current, by = fmt.Sprint(e.Current.Revision), Cell(e.Current.CreatedBy)
		}
		fmt.Fprintf(w, "| %s | %s | %s | %s | %s | %s | %s | %s |\n", e.State, e.Kind, Cell(e.Tenant), Code(e.Name), applied, current, by, Code(FormatDiff(e.Diff)))
	}
	fmt.Fprintln(w, "\nRestore with `sandboxctl rollback <kind> <name>` (back to the last applied revision), or merge a change that declares the new state.")
}

func ActionIcon(action string) string {
	switch action {
	case plan.ActionCreate:
		return "➕ create"
	case plan.ActionUpdate:
		return "✏️ update"
	case plan.ActionNoop:
		return "· noop"
	case plan.ActionInvalid:
		return "❌ invalid"
	}
	return action
}

// Failure is the block for a command that produced no result: the platform could not
// be reached or refused the request, the file could not be read, the source could not be
// verified. It opens with the same marker, so the pipeline's comment shows the failure instead
// of the previous push's plan.
func Failure(w io.Writer, what, file string, err error) {
	fmt.Fprintln(w, Marker)
	fmt.Fprintf(w, "### %s ❌ error", what)
	if file != "" {
		fmt.Fprintf(w, " · %s", Code(file))
	}
	fmt.Fprintf(w, "\n\n%s\n\n_%s produced no result; see the job log._\n", Escape(err.Error()), what)
}

// Code renders a value as a code span inside a table cell. A pipe would end the cell and a
// newline the row even inside a span, so both are escaped the way GitHub and GitLab read them
// in tables (`\|`, and a newline becomes a space); backticks would end the span.
func Code(s string) string {
	if s == "" {
		return "-"
	}
	return "`" + Escape(strings.ReplaceAll(s, "`", "'")) + "`"
}

// Cell makes a value safe inside a table cell.
func Cell(s string) string {
	if s == "" {
		return "-"
	}
	return Escape(s)
}

// Escape keeps a value on one row and inside one cell: pipes are escaped, line breaks
// (any style) become one space.
func Escape(s string) string {
	return strings.NewReplacer("|", "\\|", "\r\n", " ", "\n", " ", "\r", " ").Replace(s)
}

// FormatDiff renders a field diff on one line: +path=value for an addition, -path for a
// removal, path: from -> to for a change.
func FormatDiff(d []plan.FieldChange) string {
	parts := make([]string, 0, len(d))
	for _, f := range d {
		switch {
		case f.From == nil:
			parts = append(parts, fmt.Sprintf("+%s=%v", f.Path, f.To))
		case f.To == nil:
			parts = append(parts, fmt.Sprintf("-%s", f.Path))
		default:
			parts = append(parts, fmt.Sprintf("%s: %v -> %v", f.Path, f.From, f.To))
		}
	}
	return strings.Join(parts, ", ")
}

// ShortSHA is the first 12 digits of a commit.
func ShortSHA(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
