package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// writeHarnessFiles writes the profile's harness files (SANDBOX_HARNESS_FILES: a JSON object of
// path → content, paths relative to home) before the harness starts: a Codex config.toml, a
// Claude Code settings.json, whatever the deployment's harness reads from its home. Written on
// every run, so a profile change reaches the next run after a rollout; a file the harness
// rewrote in between is put back as the profile says. Mode 0600 in directories of 0700: the
// files are configuration, not secrets (secrets stay with the gateway), but nothing else in the
// pod needs to read them. Returns how many files it wrote.
func writeHarnessFiles(spec, home string) (int, error) {
	if strings.TrimSpace(spec) == "" {
		return 0, nil
	}
	if home == "" {
		return 0, fmt.Errorf("SANDBOX_HARNESS_FILES: HOME is not set")
	}
	var files map[string]string
	if err := json.Unmarshal([]byte(spec), &files); err != nil {
		return 0, fmt.Errorf("SANDBOX_HARNESS_FILES: %w", err)
	}
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	// The catalogue validated the paths; the runner checks again, every one before it writes
	// any, since the variable is what it reads: nothing absolute, nothing that climbs out of home.
	for _, p := range paths {
		clean := filepath.Clean(p)
		if p == "" || filepath.IsAbs(p) || clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			return 0, fmt.Errorf("SANDBOX_HARNESS_FILES: %q is not a path inside the home directory", p)
		}
	}
	for _, p := range paths {
		dst := filepath.Join(home, filepath.Clean(p))
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return 0, err
		}
		if err := os.WriteFile(dst, []byte(files[p]), 0o600); err != nil {
			return 0, err
		}
		// WriteFile keeps the mode of a file that exists; the profile's file is 0600 regardless.
		if err := os.Chmod(dst, 0o600); err != nil {
			return 0, err
		}
	}
	return len(paths), nil
}
