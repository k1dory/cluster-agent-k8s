package store

import (
	"context"
	"sync"
	"testing"
)

// Replicas start together (a rollout recreates them at once): every one applies the schema,
// and on a fresh database CREATE ... IF NOT EXISTS collides with itself. The migration runs
// under an advisory lock, so every opener succeeds.
func TestPostgresReplicasMigrateAFreshDatabaseAtOnce(t *testing.T) {
	dsn := reviewPostgresURL(t, false)
	ctx := context.Background()
	var wg sync.WaitGroup
	errs := make([]error, 6)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			p, err := OpenPostgres(ctx, dsn)
			errs[i] = err
			if err == nil {
				p.Close()
			}
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("opener %d: %v", i, err)
		}
	}
}
