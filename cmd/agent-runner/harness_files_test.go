package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The profile's files land under home, 0600 in 0700 directories, and replace what the harness
// left there since the last run.
func TestHarnessFilesAreWrittenUnderHome(t *testing.T) {
	home := t.TempDir()
	stale := filepath.Join(home, ".codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(stale), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stale, []byte("model_provider = \"openai\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	n, err := writeHarnessFiles(`{".codex/config.toml":"model_provider = \"gateway\"\n","a/b/c.json":"{}"}`, home)
	if err != nil || n != 2 {
		t.Fatalf("write: %d %v", n, err)
	}
	b, _ := os.ReadFile(stale)
	if string(b) != "model_provider = \"gateway\"\n" {
		t.Fatalf("the harness's own change survived: %q", b)
	}
	for _, p := range []string{stale, filepath.Join(home, "a", "b", "c.json")} {
		fi, err := os.Stat(p)
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", p, fi.Mode(), err)
		}
	}
	if fi, _ := os.Stat(filepath.Join(home, "a", "b")); fi.Mode().Perm() != 0o700 {
		t.Fatalf("directory mode %v", fi.Mode())
	}
	if n, err := writeHarnessFiles("", home); n != 0 || err != nil {
		t.Fatalf("no files: %d %v", n, err)
	}
}

// A path that leaves home, an absolute one, or a value that is not the JSON object is refused
// before anything is written.
func TestHarnessFilesRefuseEscapes(t *testing.T) {
	for _, spec := range []string{`{"a.txt":"x","../outside":"x"}`, `{"../outside":"x"}`, `{"/etc/passwd":"x"}`, `{"a/../../x":"x"}`, `{"":"x"}`, `["x"]`} {
		root := t.TempDir()
		home := filepath.Join(root, "home")
		if _, err := writeHarnessFiles(spec, home); err == nil {
			t.Errorf("%s: accepted", spec)
		}
		// Nothing at all: not the good file next to the bad one, not even home.
		if left, _ := filepath.Glob(filepath.Join(root, "*")); len(left) != 0 {
			t.Errorf("%s: wrote %s", spec, strings.Join(left, ", "))
		}
	}
	if _, err := writeHarnessFiles(`{"x":"y"}`, ""); err == nil {
		t.Error("an empty HOME must be refused")
	}
}
