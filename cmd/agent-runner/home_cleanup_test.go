package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// removeHomeFirst removes a test's home before t.TempDir does, trying more than once. In the
// agent images' check, os.RemoveAll of the home an agent filled has ended in ENOTEMPTY
// ("directory not empty") on .hermes with nothing left alive to write there (PR #33's
// survivor dump showed only zombies), and a static tree of the same shape removes fine on the
// same overlayfs. Why entries are still there when the final rmdir runs is not known; the
// retries are a mitigation, not a diagnosis. Registered right after t.TempDir, so it runs before
// TempDir's own removal (cleanups run last-in first-out); what a failed pass logs — the error
// and the entries still present — is the evidence for the next investigation.
func removeHomeFirst(t *testing.T, home string) {
	t.Helper()
	const tries = 5
	for i := 1; i <= tries; i++ {
		err := os.RemoveAll(home)
		if err == nil {
			if i > 1 {
				t.Logf("the home was removed on pass %d", i)
			}
			return
		}
		var left []string
		_ = filepath.WalkDir(home, func(p string, d os.DirEntry, _ error) error {
			if p != home && len(left) < 20 {
				left = append(left, p[len(home):])
			}
			return nil
		})
		t.Logf("removing the home, pass %d: %v; still there (up to 20): %q", i, err, left)
		time.Sleep(50 * time.Millisecond)
	}
}
