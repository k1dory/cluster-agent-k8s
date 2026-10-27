package ca

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The files Caddy reads: the certificate world-readable, the key readable by the owner and
// the group (the pod's fsGroup lets Caddy, under another user with no CAP_DAC_OVERRIDE, read
// what sandboxd wrote), never by others.
func TestWriteToModes(t *testing.T) {
	c, err := Generate("test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "root")
	certPath, keyPath, err := c.WriteTo(dir, "gateway-root")
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]os.FileMode{certPath: 0o644, keyPath: 0o640} {
		st, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != want {
			t.Errorf("%s: mode %o, want %o", path, st.Mode().Perm(), want)
		}
	}
}
