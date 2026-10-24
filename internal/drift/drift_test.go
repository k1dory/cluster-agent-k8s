package drift

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"agent-sandbox/internal/model"
	"agent-sandbox/internal/store"
)

func put(t *testing.T, st store.Catalog, kind, tenant, name, spec, by string, src *model.Source) *model.CatalogItem {
	t.Helper()
	it := &model.CatalogItem{Kind: kind, Tenant: tenant, Name: name, Spec: json.RawMessage(spec), CreatedBy: by, Source: src}
	if err := st.PutItem(context.Background(), it, -1); err != nil {
		t.Fatal(err)
	}
	return it
}

func TestDetect(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	now := time.Now()
	applied := &model.Source{Apply: "apply_1", Bundle: "b1", Commit: "abc"}
	// In sync: the latest revision was written by an apply.
	put(t, st, model.KindEnvironment, "acme", "py", `{"image":"stable"}`, "ci", applied)
	// Changed: an apply wrote revision 1, a person wrote revision 2.
	put(t, st, model.KindAgent, "acme", "backend", `{"policy":"p","environment":"py@1"}`, "ci", applied)
	put(t, st, model.KindAgent, "acme", "backend", `{"policy":"p","environment":"py@1","repo":"x"}`, "mallory", nil)
	// Deleted: an apply wrote it, then it was removed.
	put(t, st, model.KindConnection, "acme", "github", `{"type":"http","host":"api.github.com"}`, "ci", applied)
	if err := st.DeleteItem(ctx, model.KindConnection, "acme", "github"); err != nil {
		t.Fatal(err)
	}
	// Manual only: never applied, not drift.
	put(t, st, model.KindEnvironment, "acme", "scratch", `{"image":"stable"}`, "alice", nil)
	// Superseded by a later apply: the desired state moved, not drift.
	put(t, st, model.KindEnvironment, "acme", "go", `{"image":"stable"}`, "ci", applied)
	put(t, st, model.KindEnvironment, "acme", "go", `{"image":"canary"}`, "ci", &model.Source{Apply: "apply_2", Bundle: "b2"})
	// Another tenant's drift is not acme's.
	put(t, st, model.KindEnvironment, "other", "py", `{"image":"stable"}`, "ci", applied)
	put(t, st, model.KindEnvironment, "other", "py", `{"image":"canary"}`, "bob", nil)

	rep, err := Detect(ctx, st, "acme", now)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Checked != 4 || len(rep.Drifted) != 2 {
		t.Fatalf("report: %+v", rep)
	}
	byName := map[string]Entry{}
	for _, e := range rep.Drifted {
		byName[e.Name] = e
	}
	gh := byName["github"]
	if gh.State != Deleted || gh.Kind != model.KindConnection || gh.Applied.Revision != 1 || gh.Applied.Source.Apply != "apply_1" || gh.Current != nil {
		t.Fatalf("deleted: %+v", gh)
	}
	be := byName["backend"]
	if be.State != Changed || be.Applied.Revision != 1 || be.Current == nil || be.Current.Revision != 2 || be.Current.CreatedBy != "mallory" {
		t.Fatalf("changed: %+v", be)
	}
	if len(be.Diff) != 1 || be.Diff[0].Path != "spec.repo" || be.Diff[0].To != "x" {
		t.Fatalf("diff: %+v", be.Diff)
	}
	other, _ := Detect(ctx, st, "other", now)
	if len(other.Drifted) != 1 || other.Drifted[0].Tenant != "other" {
		t.Fatalf("other tenant: %+v", other)
	}
	shared, _ := Detect(ctx, st, "", now)
	if len(shared.Drifted) != 0 || shared.Checked != 0 {
		t.Fatalf("shared: %+v", shared)
	}
	// A deleted item written again by hand is changed, not deleted; the last applied revision
	// is still the reference.
	put(t, st, model.KindConnection, "acme", "github", `{"type":"http","host":"api.github.com","headers":{"X":"y"}}`, "alice", nil)
	rep, _ = Detect(ctx, st, "acme", now)
	if e := find(rep, "github"); e == nil || e.State != Changed || e.Applied.Revision != 1 || e.Current.Revision != 2 {
		t.Fatalf("recreated: %+v", rep)
	}
}

func find(rep *Report, name string) *Entry {
	for i := range rep.Drifted {
		if rep.Drifted[i].Name == name {
			return &rep.Drifted[i]
		}
	}
	return nil
}
