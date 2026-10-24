package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The chart renders api_keys.max_ttl as a quoted string ("0", "720h"); both must load as a
// duration, and the example configuration must load at all.
func TestAPIKeysMaxTTLParsesQuotedDurations(t *testing.T) {
	dir := t.TempDir()
	for raw, want := range map[string]time.Duration{`"0"`: 0, `"720h"`: 720 * time.Hour, `30m`: 30 * time.Minute} {
		path := filepath.Join(dir, "c.yaml")
		if err := os.WriteFile(path, []byte("api_token: x\nruntime: fake\napi_keys:\n  max_ttl: "+raw+"\npolicies_dir: policies\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		c, err := Load(path)
		if err != nil || c.APIKeys.MaxTTL != want {
			t.Fatalf("max_ttl %s: %v %v", raw, err, c)
		}
	}
	if _, err := Load("../../config/sandboxd.example.yaml"); err != nil {
		t.Fatalf("example config: %v", err)
	}
}
