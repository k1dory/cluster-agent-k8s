package ca

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Caddy reads the shared root through the pod's group under a different UID.
// Every directory WriteTo creates below the shared mount must allow that group
// to reach the files, including when gateway.root_dir names a nested directory.
func TestReviewSharedRootDirectoriesAllowCaddyGroupTraversal(t *testing.T) {
	for _, relative := range []string{"gateway-root", "nested/gateway-root"} {
		t.Run(relative, func(t *testing.T) {
			shared := t.TempDir()
			if err := os.Chmod(shared, 0o750); err != nil {
				t.Fatal(err)
			}
			root, err := Generate("review shared gateway root", time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			_, keyPath, err := root.WriteTo(filepath.Join(shared, relative), "gateway-root")
			if err != nil {
				t.Fatal(err)
			}
			for dir := filepath.Dir(keyPath); dir != shared; dir = filepath.Dir(dir) {
				info, err := os.Stat(dir)
				if err != nil {
					t.Fatal(err)
				}
				if info.Mode().Perm()&0o010 == 0 {
					t.Errorf("shared-root directory %s has mode %04o: Caddy's group cannot traverse it to read the root", filepath.Base(dir), info.Mode().Perm())
				}
			}
		})
	}
}
