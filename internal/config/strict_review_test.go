package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadString(t *testing.T, body string) error {
	t.Helper()
	f := filepath.Join(t.TempDir(), "sandboxd.yaml")
	if err := os.WriteFile(f, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(f)
	return err
}

// A misspelt key was silently ignored, leaving the setting at its default.
func TestReviewUnknownConfigKeyFailsAtStartup(t *testing.T) {
	err := loadString(t, "runtime: fake\ngateway:\n  sync_evrey: 1s\n")
	if err == nil || !strings.Contains(err.Error(), "sync_evrey") {
		t.Fatalf("a typo'd key must fail: %v", err)
	}
	if err := loadString(t, "runtime: fake\ngateway:\n  sync_every: 1s\n"); err != nil {
		t.Fatalf("a known key loads: %v", err)
	}
	if err := loadString(t, "# comments only\n"); err != nil && strings.Contains(err.Error(), "EOF") {
		t.Fatalf("a file without settings must decode as the defaults: %v", err)
	}
}

func TestReviewNegativeDurationIsRefused(t *testing.T) {
	err := loadString(t, "runtime: fake\ngateway:\n  sync_every: -5s\n")
	if err == nil || !strings.Contains(err.Error(), "gateway.sync_every") {
		t.Fatalf("a negative duration must be refused with its key: %v", err)
	}
	err = loadString(t, "runtime: fake\ncredentials:\n  oauth:\n    refresh_before: -1m\n")
	if err == nil || !strings.Contains(err.Error(), "credentials.oauth.refresh_before") {
		t.Fatalf("nested: %v", err)
	}
}
