package ci

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A registry read error must not turn an existing immutable tag into a new build.
// Both tools are inert fixtures: this test neither builds nor publishes an image.
func TestReviewPublishStopsWhenExistingTagCannotBeRead(t *testing.T) {
	dir, _ := checkout(t)
	bin, dockerLog, _ := publishStubs(t, "")
	stub(t, bin, "docker", `printf '%s\n' "$*" >> "`+dockerLog+`"
case "$1 ${2:-} ${3:-}" in
  "buildx imagetools inspect") echo 'fixture: registry temporarily unavailable (503)' >&2; exit 1 ;;
  "buildx build "*) echo 'fixture: stopped before building' >&2; exit 74 ;;
  *) exit 0 ;;
esac
`)
	out, err := runScript(t, "hack/publish-images.sh", map[string]string{
		"CI_ROOT": dir, "IMAGE_REPO": "registry.example.com/review/images",
		"COSIGN_PRIVATE_KEY": "fixture-key", "COSIGN_BIN": filepath.Join(bin, "cosign"),
	}, bin)
	if err == nil {
		t.Fatalf("publication must fail when registry state is unknown: %s", out)
	}
	calls, err := os.ReadFile(dockerLog)
	if err != nil || !strings.Contains(string(calls), "buildx imagetools inspect") {
		t.Fatalf("fixture never reached the registry lookup: %v\n%s", err, out)
	}
	if strings.Contains(string(calls), "buildx build") {
		t.Fatal("registry lookup failed, but publication proceeded to build and push the tag")
	}
}
