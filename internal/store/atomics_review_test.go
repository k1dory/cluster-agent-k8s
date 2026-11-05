package store

import (
	"errors"
	"sync"
	"testing"
	"time"

	"agent-sandbox/internal/model"
)

func bothStores(t *testing.T, body func(t *testing.T, st Store)) {
	t.Run("memory", func(t *testing.T) { body(t, NewMemory()) })
	t.Run("postgres", func(t *testing.T) { body(t, reviewOpenPostgres(t, reviewPostgresURL(t, false))) })
}

func TestReviewRotateAPIKeyIsAtomic(t *testing.T) {
	bothStores(t, func(t *testing.T, st Store) {
		ctx := t.Context()
		now := time.Now().UTC().Truncate(time.Millisecond)
		key := func(id string) *model.APIKey {
			return &model.APIKey{ID: id, Tenant: "acme", Name: "ci", Hash: "h-" + id, CreatedAt: now}
		}
		if err := st.CreateAPIKey(ctx, key("old")); err != nil {
			t.Fatal(err)
		}
		if err := st.CreateAPIKey(ctx, key("taken")); err != nil {
			t.Fatal(err)
		}
		// A failing step (the successor's id exists) changes nothing.
		if err := st.RotateAPIKey(ctx, "old", key("taken"), now, time.Hour); !errors.Is(err, ErrConflict) {
			t.Fatalf("duplicate successor: %v", err)
		}
		if k, _ := st.GetAPIKey(ctx, "old"); k.RotatedTo != "" || k.ExpiresAt != nil || k.RevokedAt != nil {
			t.Fatalf("a failed rotation must leave the old key as it was: %+v", k)
		}
		if err := st.RotateAPIKey(ctx, "old", key("s1"), now, time.Hour); err != nil {
			t.Fatal(err)
		}
		if k, _ := st.GetAPIKey(ctx, "old"); k.RotatedTo != "s1" || k.ExpiresAt == nil || !k.ExpiresAt.Equal(now.Add(time.Hour)) {
			t.Fatalf("old retired to s1 within grace: %+v", k)
		}
		// Rotating again: the unused s1 is withdrawn in the same step, unless that step fails.
		if err := st.RotateAPIKey(ctx, "old", key("taken"), now, time.Hour); !errors.Is(err, ErrConflict) {
			t.Fatalf("duplicate successor: %v", err)
		}
		if k, _ := st.GetAPIKey(ctx, "s1"); !k.Active(now) {
			t.Fatal("a failed later write must not withdraw the earlier successor")
		}
		if err := st.RotateAPIKey(ctx, "old", key("s2"), now, time.Hour); err != nil {
			t.Fatal(err)
		}
		if k, _ := st.GetAPIKey(ctx, "s1"); k.Active(now) {
			t.Fatal("the unused earlier successor is withdrawn")
		}
		// Once used, the successor stands and the rotation is refused.
		if err := st.TouchAPIKey(ctx, "s2", now); err != nil {
			t.Fatal(err)
		}
		var inUse *SuccessorInUseError
		if err := st.RotateAPIKey(ctx, "old", key("s3"), now, time.Hour); !errors.As(err, &inUse) || inUse.ID != "s2" {
			t.Fatalf("an in-use successor must be refused: %v", err)
		}
		if _, err := st.GetAPIKey(ctx, "s3"); !errors.Is(err, ErrNotFound) {
			t.Fatal("a refused rotation inserts nothing")
		}
		if err := st.RevokeAPIKey(ctx, "old", now); err != nil {
			t.Fatal(err)
		}
		if err := st.RotateAPIKey(ctx, "old", key("s4"), now.Add(time.Second), 0); !errors.Is(err, ErrKeyInactive) {
			t.Fatalf("a revoked key cannot be rotated: %v", err)
		}
	})
}

// A first use of the successor racing a second rotation: either the use is seen and the
// rotation refused, or the rotation withdraws a successor nobody had used yet. Never both a
// withdrawn successor and a refused rotation, and at most one live successor.
func TestReviewRotateAPIKeyRacesFirstUse(t *testing.T) {
	bothStores(t, func(t *testing.T, st Store) {
		ctx := t.Context()
		now := time.Now().UTC().Truncate(time.Millisecond)
		for i := range 20 {
			id := func(s string) string { return s + "-" + string(rune('a'+i)) }
			if err := st.CreateAPIKey(ctx, &model.APIKey{ID: id("old"), Tenant: "acme", Name: "ci", Hash: id("h"), CreatedAt: now}); err != nil {
				t.Fatal(err)
			}
			if err := st.RotateAPIKey(ctx, id("old"), &model.APIKey{ID: id("s1"), Tenant: "acme", Name: "ci", Hash: id("h1")}, now, time.Hour); err != nil {
				t.Fatal(err)
			}
			var wg sync.WaitGroup
			var rotErr error
			wg.Go(func() { _ = st.TouchAPIKey(ctx, id("s1"), now) })
			wg.Go(func() {
				rotErr = st.RotateAPIKey(ctx, id("old"), &model.APIKey{ID: id("s2"), Tenant: "acme", Name: "ci", Hash: id("h2")}, now, time.Hour)
			})
			wg.Wait()
			s1, _ := st.GetAPIKey(ctx, id("s1"))
			var inUse *SuccessorInUseError
			switch {
			case rotErr == nil:
				if s1.Active(now) {
					t.Fatalf("round %d: rotation succeeded but s1 is still live", i)
				}
			case errors.As(rotErr, &inUse):
				if !s1.Active(now) {
					t.Fatalf("round %d: rotation refused yet s1 withdrawn", i)
				}
			default:
				t.Fatalf("round %d: %v", i, rotErr)
			}
		}
	})
}

func TestReviewSwapBlobHasOneWinner(t *testing.T) {
	bothStores(t, func(t *testing.T, st Store) {
		ctx := t.Context()
		if _, err := st.GetOrCreateBlob(ctx, "ca", func() ([]byte, error) { return []byte("plain"), nil }); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		var mu sync.Mutex
		wins := 0
		for i := range 8 {
			wg.Go(func() {
				ok, err := st.SwapBlob(ctx, "ca", []byte("plain"), []byte{'s', byte('0' + i)})
				if err != nil {
					t.Error(err)
				}
				if ok {
					mu.Lock()
					wins++
					mu.Unlock()
				}
			})
		}
		wg.Wait()
		if wins != 1 {
			t.Fatalf("exactly one swap from the same original must win, got %d", wins)
		}
		if _, err := st.SwapBlob(ctx, "missing", nil, []byte("x")); !errors.Is(err, ErrNotFound) {
			t.Fatalf("absent blob: %v", err)
		}
	})
}

func TestReviewBindInstanceIsIdempotentPerPodAndSerial(t *testing.T) {
	bothStores(t, func(t *testing.T, st Store) {
		ctx := t.Context()
		now := time.Now().UTC().Truncate(time.Millisecond)
		if err := st.CreateSandbox(ctx, &model.Sandbox{ID: "sb-bind", Name: "n", Slug: "dev", Owner: "o", Tenant: "acme", Status: model.StatusRunning, CreatedAt: now, LastActivity: now}); err != nil {
			t.Fatal(err)
		}
		issue := func(serial string) func(int, *model.Instance) (*model.Instance, error) {
			return func(n int, ex *model.Instance) (*model.Instance, error) {
				if ex != nil {
					return ex, nil
				}
				return &model.Instance{SandboxID: "sb-bind", Slug: "dev", Tenant: "acme", PodName: "pod-a", Serial: serial, IssuedAt: now, NotAfter: now.Add(time.Hour)}, nil
			}
		}
		var wg sync.WaitGroup
		results := make([]*BoundInstance, 6)
		errs := make([]error, 6)
		for i := range results {
			wg.Go(func() {
				results[i], errs[i] = st.BindInstance(ctx, InstanceBinding{SandboxID: "sb-bind", PodName: "pod-a", Serial: "aa01"}, issue("aa01"))
			})
		}
		wg.Wait()
		for i := range results {
			if errs[i] != nil || results[i].Instance.N != results[0].Instance.N || results[i].Instance.Serial != "aa01" {
				t.Fatalf("every bootstrap with the same key gets the same identity: %v %+v", errs[i], results[i])
			}
		}
		n := results[0].Instance.N
		sb, _ := st.GetSandbox(ctx, "sb-bind")
		if sb.Instance != n || sb.PodName != "pod-a" {
			t.Fatalf("sandbox records the identity: %+v", sb)
		}
		// A new key from the same pod (the init container restarted) replaces the identity.
		b, err := st.BindInstance(ctx, InstanceBinding{SandboxID: "sb-bind", PodName: "pod-a", Serial: "bb02"}, issue("bb02"))
		if err != nil || b.Reused || b.Instance.N == n || len(b.Retired) != 1 || b.Retired[0] != n {
			t.Fatalf("new key: %v %+v", err, b)
		}
		ins, _ := st.ListInstances(ctx, "sb-bind")
		live := 0
		for _, in := range ins {
			if in.RetiredAt == nil {
				live++
			}
		}
		if live != 1 {
			t.Fatalf("one live identity per pod, got %d", live)
		}
		// An issue error aborts everything.
		if _, err := st.BindInstance(ctx, InstanceBinding{SandboxID: "sb-bind", PodName: "pod-a", Serial: "cc03"}, func(int, *model.Instance) (*model.Instance, error) {
			return nil, errors.New("sign failed")
		}); err == nil {
			t.Fatal("issue error must fail the bind")
		}
		if in, _ := st.InstanceBySerial(ctx, "bb02"); in == nil || in.RetiredAt != nil {
			t.Fatal("a failed bind must not retire the live identity")
		}
		// Another pod while pod-a is current: its own identity, pod-a stays current.
		other, err := st.BindInstance(ctx, InstanceBinding{SandboxID: "sb-bind", PodName: "pod-b", Serial: "dd04"}, func(n int, ex *model.Instance) (*model.Instance, error) {
			return &model.Instance{SandboxID: "sb-bind", Slug: "dev", Tenant: "acme", PodName: "pod-b", Serial: "dd04", IssuedAt: now, NotAfter: now.Add(time.Hour)}, nil
		})
		if err != nil || other.Current != "pod-a" || len(other.Retired) != 0 {
			t.Fatalf("other pod: %v %+v", err, other)
		}
		if _, err := st.BindInstance(ctx, InstanceBinding{SandboxID: "nope", PodName: "p", Serial: "x"}, issue("x")); !errors.Is(err, ErrNotFound) {
			t.Fatalf("unknown sandbox: %v", err)
		}
	})
}
