package ci_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every package whose tests take a real database (they read SANDBOX_TEST_POSTGRES_URL) must
// be run by the postgres job: the unit job has no database, so a package missing here has its
// Postgres branch skipped in every CI run (the CA upgrade test was).
func TestPostgresJobRunsEveryPackageWithDatabaseTests(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	script, err := os.ReadFile(filepath.Join(root, "hack/ci/postgres.sh"))
	if err != nil {
		t.Fatal(err)
	}
	pkgs := map[string]bool{}
	err = filepath.WalkDir(filepath.Join(root, "internal"), func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, "_test.go") {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(b), `Getenv("SANDBOX_TEST_POSTGRES_URL")`) {
			rel, _ := filepath.Rel(root, filepath.Dir(path))
			pkgs[filepath.ToSlash(rel)] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) == 0 {
		t.Fatal("found no database tests at all")
	}
	for p := range pkgs {
		if !strings.Contains(string(script), "./"+p+"/") {
			t.Errorf("hack/ci/postgres.sh does not run ./%s/, whose tests need SANDBOX_TEST_POSTGRES_URL", p)
		}
	}
}
