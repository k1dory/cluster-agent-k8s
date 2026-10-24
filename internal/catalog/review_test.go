package catalog

import (
	"encoding/json"
	"errors"
	"testing"

	"agent-sandbox/internal/model"
)

func reviewPut(t *testing.T, s *Service, kind, tenant, name, spec string, admin bool) *model.CatalogItem {
	t.Helper()
	item, err := s.Put(t.Context(), kind, tenant, doc(t, name, spec, nil), admin, "review")
	if err != nil {
		t.Fatal(err)
	}
	return item
}

func TestReviewPinnedEnvironmentCannotBeReplacedByRecreatedName(t *testing.T) {
	s := newService()
	reviewPut(t, s, model.KindEnvironment, "acme", "base", `{"image":"stable"}`, false)
	reviewPut(t, s, model.KindAgent, "acme", "worker", `{"policy":"backend-dev","environment":"base@1"}`, false)
	before, err := s.Resolve(t.Context(), "acme", "worker@1", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(t.Context(), model.KindEnvironment, "acme", "base"); err != nil {
		if errors.Is(err, ErrConflict) || errors.Is(err, ErrForbidden) {
			return
		}
		t.Fatal(err)
	}
	_, err = s.Put(t.Context(), model.KindEnvironment, "acme", doc(t, "base", `{"image":"canary"}`, nil), false, "review")
	if errors.Is(err, ErrConflict) {
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	after, err := s.Resolve(t.Context(), "acme", "worker@1", false)
	if errors.Is(err, ErrNotFound) {
		return
	} // A deleted revision may become unavailable, never a new value.
	if err != nil {
		t.Fatal(err)
	}
	if after.Launch.Image != before.Launch.Image {
		t.Fatalf("worker@1 still pins base@1, but delete/recreate changed its image: %q -> %q", before.Launch.Image, after.Launch.Image)
	}
}

func TestReviewPinnedEnvironmentKeepsItsScope(t *testing.T) {
	s := newService()
	reviewPut(t, s, model.KindEnvironment, "", "base", `{"image":"stable"}`, true)
	reviewPut(t, s, model.KindAgent, "acme", "worker", `{"policy":"backend-dev","environment":"base@1"}`, false)
	before, err := s.Resolve(t.Context(), "acme", "worker@1", false)
	if err != nil {
		t.Fatal(err)
	}
	// An unrelated local environment now shadows the same shared name and revision number.
	reviewPut(t, s, model.KindEnvironment, "acme", "base", `{"image":"canary"}`, false)
	after, err := s.Resolve(t.Context(), "acme", "worker@1", false)
	if err != nil {
		t.Fatal(err)
	}
	if before.Environment.Tenant != after.Environment.Tenant || before.Launch.Image != after.Launch.Image {
		t.Fatalf("pinned dependency changed without changing worker@1: scope %q -> %q, image %q -> %q", before.Environment.Tenant, after.Environment.Tenant, before.Launch.Image, after.Launch.Image)
	}
}

func TestReviewCatalogRejectsTrailingDocuments(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		parse     func([]byte) (*Document, error)
	}{
		{"json", `{"kind":"EnvironmentProfile","name":"base","spec":{"image":"stable"}} {"unexpected":true}`, ParseJSON},
		{"yaml", "kind: EnvironmentProfile\nname: base\nspec: {image: stable}\n---\nkind: AgentDefinition\nname: silently-ignored\nspec: {}\n", ParseYAML},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if d, err := tc.parse([]byte(tc.raw)); err == nil {
				b, _ := json.Marshal(d)
				t.Fatalf("single-document parser silently discarded trailing input: %s", b)
			}
		})
	}
}
