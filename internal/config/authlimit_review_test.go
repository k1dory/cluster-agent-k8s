package config

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"agent-sandbox/internal/httpapi"
)

func loadAuthLimit(t *testing.T, block string) (*Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sandboxd.yaml")
	if err := os.WriteFile(path, []byte("api_token: x\nruntime: fake\npolicies_dir: policies\n"+block), 0o644); err != nil {
		t.Fatal(err)
	}
	return Load(path)
}

// auth_limit is read from the file, and what is read is what the handler applies.
func TestAuthLimitConfigReachesTheHandler(t *testing.T) {
	c, err := loadAuthLimit(t, "")
	if err != nil || c.AuthLimit != (httpapi.RateLimit{}) {
		t.Fatalf("absent: %+v %v (the zero value is on with the defaults)", c.AuthLimit, err)
	}
	c, err = loadAuthLimit(t, "auth_limit:\n  burst: 2\n  every: 1h\n")
	if err != nil || c.AuthLimit != (httpapi.RateLimit{Burst: 2, Every: time.Hour}) {
		t.Fatalf("set: %+v %v", c.AuthLimit, err)
	}
	for _, bad := range []string{"auth_limit:\n  burst: -1\n", "auth_limit:\n  every: -1s\n"} {
		if _, err := loadAuthLimit(t, bad); err == nil {
			t.Fatalf("negative accepted: %q", bad)
		}
	}
	off, err := loadAuthLimit(t, "auth_limit:\n  off: true\n  burst: 1\n")
	if err != nil || !off.AuthLimit.Off {
		t.Fatalf("off: %+v %v", off.AuthLimit, err)
	}

	// The handler sandboxd builds (platform.AuthLimit = cfg.AuthLimit) applies what was read.
	codes := func(rl httpapi.RateLimit) []int {
		srv := httptest.NewServer((&httpapi.Platform{Token: "admin", AuthLimit: rl}).Routes())
		defer srv.Close()
		var out []int
		for i := 0; i < 3; i++ {
			req, _ := http.NewRequest("GET", srv.URL+"/v1/whoami", nil)
			req.Header.Set("Authorization", "Bearer guess")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			out = append(out, resp.StatusCode)
		}
		return out
	}
	if got := codes(c.AuthLimit); got[0] != 401 || got[1] != 401 || got[2] != 429 {
		t.Fatalf("burst 2 from the file: %v", got)
	}
	if got := codes(off.AuthLimit); got[2] != 401 {
		t.Fatalf("off from the file: %v", got)
	}
}
