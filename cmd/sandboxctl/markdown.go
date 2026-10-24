package main

import (
	"fmt"
	"io"
	"strings"

	"agent-sandbox/internal/drift"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/plan"
)

// Markdown renderers for the Git adapters: a plan as the comment on a pull request, an apply
// as the job summary of the merge, a drift report as the body of the alert. Each starts with a
// marker line so a pipeline can find and update its own comment instead of adding one per push.

// Marker opens every rendered block (an HTML comment: invisible on GitHub and GitLab).
const Marker = "<!-- agent-sandbox -->"

func markdownPlan(w io.Writer, p plan.Plan, file string) {
	fmt.Fprintln(w, Marker)
	verdict := "✅ valid"
	if !p.Valid {
		verdict = "❌ invalid"
	}
	fmt.Fprintf(w, "### Plan %s", verdict)
	if file != "" {
		fmt.Fprintf(w, " · `%s`", file)
	}
	fmt.Fprintf(w, "\n\n%d to create, %d to update, %d unchanged, %d invalid · bundle `%s` · plan `%s`\n\n",
		p.Summary.Create, p.Summary.Update, p.Summary.Noop, p.Summary.Invalid, p.Bundle, p.Fingerprint)
	for _, e := range p.Errors {
		fmt.Fprintf(w, "- ❌ bundle: %s\n", mdEscape(e))
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
			detail = "❌ " + mdEscape(strings.Join(c.Errors, "; "))
		case c.Action == plan.ActionNoop:
		default:
			detail = mdCode(formatDiff(c.Diff))
		}
		rev := fmt.Sprintf("%d → %d", c.CurrentRevision, c.NextRevision)
		if c.Action == plan.ActionNoop || c.Action == plan.ActionInvalid {
			rev = fmt.Sprint(c.CurrentRevision)
		}
		fmt.Fprintf(w, "| %s | %s | %s | `%s` | %s | %s |\n", actionIcon(c.Action), c.Kind, mdCell(c.Tenant), c.Name, rev, detail)
	}
	if !p.Valid {
		fmt.Fprintln(w, "\nThe bundle is not valid: `apply` on merge would be refused. Fix the documents above before merging.")
	} else if p.Summary.Create+p.Summary.Update == 0 {
		fmt.Fprintln(w, "\nNothing would change: the platform already holds this bundle.")
	} else {
		fmt.Fprintln(w, "\nMerging applies exactly these changes (one transaction per step, continued by key), with this commit as the source of every new revision.")
	}
}

func markdownApply(w io.Writer, a model.Apply) {
	fmt.Fprintln(w, Marker)
	icon := map[string]string{model.ApplyDone: "✅", model.ApplyFailed: "❌", model.ApplyConflict: "⚠️", model.ApplyRunning: "⏳"}[a.Status]
	fmt.Fprintf(w, "### Apply %s %s · `%s`\n\n", icon, a.Status, a.ID)
	if a.Error != "" {
		fmt.Fprintf(w, "%s\n\n", mdEscape(a.Error))
	}
	if a.Source != nil && a.Source.Commit != "" {
		fmt.Fprintf(w, "Source: `%s`", a.Source.Commit)
		if a.Source.Repo != "" {
			fmt.Fprintf(w, " in %s", a.Source.Repo)
		}
		if a.Source.Path != "" {
			fmt.Fprintf(w, " (`%s`)", a.Source.Path)
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
		fmt.Fprintf(w, "| %d | %s | %s | `%s` | %s | %s | %s | %s |\n", i+1, st.Kind, mdCell(st.Tenant), st.Name, actionIcon(st.Action), st.Status, rev, mdCell(st.Error))
	}
	if a.Status != model.ApplyDone {
		fmt.Fprintf(w, "\nContinue with `sandboxctl apply -resume %s` once the cause is fixed; the applied steps stay as they are.\n", a.ID)
	}
}

func markdownDrift(w io.Writer, rep drift.Report) {
	fmt.Fprintln(w, Marker)
	if len(rep.Drifted) == 0 {
		fmt.Fprintf(w, "### Drift ✅ none · %d managed items\n", rep.Checked)
		return
	}
	fmt.Fprintf(w, "### Drift ⚠️ %d of %d managed items\n\n", len(rep.Drifted), rep.Checked)
	fmt.Fprintln(w, "| State | Kind | Tenant | Name | Applied | Current | By | Changes |")
	fmt.Fprintln(w, "|---|---|---|---|---|---|---|---|")
	for _, e := range rep.Drifted {
		applied := fmt.Sprintf("%d (`%s`", e.Applied.Revision, e.Applied.Source.Apply)
		if e.Applied.Source.Commit != "" {
			applied += " @ `" + shortSHA(e.Applied.Source.Commit) + "`"
		}
		applied += ")"
		current, by := "-", "-"
		if e.Current != nil {
			current, by = fmt.Sprint(e.Current.Revision), mdCell(e.Current.CreatedBy)
		}
		fmt.Fprintf(w, "| %s | %s | %s | `%s` | %s | %s | %s | %s |\n", e.State, e.Kind, mdCell(e.Tenant), e.Name, applied, current, by, mdCode(formatDiff(e.Diff)))
	}
	fmt.Fprintln(w, "\nRestore with `sandboxctl rollback <kind> <name>` (back to the last applied revision), or merge a change that declares the new state.")
}

func actionIcon(action string) string {
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

// mdCode wraps a non-empty diff in backticks (a table cell cannot hold a fenced block).
func mdCode(s string) string {
	if s == "" {
		return "-"
	}
	return "`" + strings.ReplaceAll(s, "`", "'") + "`"
}

// mdCell makes a value safe inside a table cell.
func mdCell(s string) string {
	if s == "" {
		return "-"
	}
	return mdEscape(s)
}

func mdEscape(s string) string {
	return strings.NewReplacer("|", "\\|", "\n", " ").Replace(s)
}
