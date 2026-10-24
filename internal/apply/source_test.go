package apply

import (
	"errors"
	"strings"
	"testing"

	"agent-sandbox/internal/model"
	res "agent-sandbox/internal/resource"
)

func TestCleanSourceStripsCredentials(t *testing.T) {
	cases := map[string]string{
		"https://x-access-token:ghp_secret@github.com/acme/platform.git": "https://github.com/acme/platform.git",
		"https://ghp_secret@github.com/acme/platform.git":                "https://github.com/acme/platform.git",
		"https://github.com/acme/platform.git":                           "https://github.com/acme/platform.git",
		"ssh://git@github.com/acme/platform.git":                         "ssh://github.com/acme/platform.git",
		"git@github.com:acme/platform.git":                               "git@github.com:acme/platform.git",
		"deploy-token-abc@github.com:acme/platform.git":                  "github.com:acme/platform.git",
		"user:pass@github.com:acme/platform.git":                         "github.com:acme/platform.git",
		"github.com:acme/platform.git":                                   "github.com:acme/platform.git",
		"":                                                               "",
	}
	for in, want := range cases {
		s := &model.Source{Repo: in, Commit: strings.Repeat("ab", 20)}
		if err := CleanSource(s); err != nil || s.Repo != want {
			t.Errorf("%q: %v → %q, want %q", in, err, s.Repo, want)
		}
	}
	// The commit must be an object name; other junk is refused rather than stored.
	for _, bad := range []string{"main", "ghp_secret", "0123456", "x"} {
		err := CleanSource(&model.Source{Commit: bad})
		if bad == "0123456" {
			if err != nil {
				t.Errorf("short SHA refused: %v", err)
			}
			continue
		}
		if !errors.Is(err, res.ErrInvalid) {
			t.Errorf("commit %q accepted: %v", bad, err)
		}
	}
	if err := CleanSource(&model.Source{Path: strings.Repeat("p", 600)}); !errors.Is(err, res.ErrInvalid) {
		t.Errorf("oversized field accepted: %v", err)
	}
	if s := (&model.Source{Commit: " ABCDEF0123 "}); CleanSource(s) != nil || s.Commit != "abcdef0123" {
		t.Errorf("commit not normalised: %+v", s)
	}
}
