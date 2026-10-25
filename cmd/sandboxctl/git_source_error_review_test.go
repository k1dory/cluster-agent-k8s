package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReviewGitSourceDoesNotHideMetadataFailure(t *testing.T) {
	_, file := reviewGitBundle(t)
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	// A checkout exists, but Git cannot inspect it (for example, the CI image and the
	// mounted checkout use different owners). The adapter must not silently lose its SHA.
	bin := t.TempDir()
	stub := "#!/bin/sh\nprintf '%s\\n' 'fatal: cannot inspect checkout metadata' >&2\nexit 128\n"
	if err := os.WriteFile(filepath.Join(bin, "git"), []byte(stub), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	_, _, _, err = gitSource(file, raw)
	if err == nil {
		t.Error("failure to inspect an existing Git checkout must be reported instead of applying without provenance")
	}
}
