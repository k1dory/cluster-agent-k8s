package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// removeHomeFirst removes a test's home before t.TempDir does, trying more than once. The agent
// images' check runs on a container filesystem (overlayfs) where os.RemoveAll of a directory
// the agent filled with many entries can end in "directory not empty" with nothing left
// alive to write there (PR #33's survivor dump showed only zombies): the directory listing
// read while entries are being unlinked misses some, RemoveAll stops early and the final rmdir
// fails. A second pass sees what the first missed. Registered right after t.TempDir, so it
// runs before TempDir's own removal (cleanups run last-in first-out); what it logs on a slow
// pass is the evidence for the next investigation.
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
