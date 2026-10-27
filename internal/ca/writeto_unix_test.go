//go:build unix

package ca

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// The directories WriteTo creates, nested ones included, let the group through (Caddy reads
// the root under the pod's fsGroup), whatever the umask: 077 would leave them 0700. A
// directory already in place (the volume's mount point) keeps its mode.
func TestWriteToDirectoriesLetTheGroupThrough(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	c, err := Generate("test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	mount := filepath.Join(base, "mount")
	if err := os.Mkdir(mount, 0o700); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(mount, "gateway", "root")
	if _, keyPath, err := c.WriteTo(dir, "gateway-root"); err != nil {
		t.Fatal(err)
	} else if st, err := os.Stat(keyPath); err != nil || st.Mode().Perm() != 0o640 {
		t.Fatalf("key: %v, mode %o", err, st.Mode().Perm())
	}
	for _, d := range []string{filepath.Join(mount, "gateway"), dir} {
		st, err := os.Stat(d)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o750 {
			t.Errorf("%s: mode %o, want 0750 (group traversal)", d, st.Mode().Perm())
		}
	}
	if st, _ := os.Stat(mount); st.Mode().Perm() != 0o700 {
		t.Errorf("the directory found in place was changed to %o", st.Mode().Perm())
	}
}
