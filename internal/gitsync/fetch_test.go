package gitsync

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"agent-sandbox/internal/gitsync/gittest"
)

func TestCLIReadsASmartHTTPRepositoryWithACredential(t *testing.T) {
	g := gittest.New(t, "x-access-token", "tok-secret-1")
	url, commit := g.URL, func(files map[string]string, msg string) string { return g.Commit(t, files, msg) }
	sha1 := commit(map[string]string{"bundles/acme.yaml": "kind: EnvironmentProfile\nname: py\nspec: {image: stable}\n", "README.md": "hi\n"}, "one")
	sha2 := commit(map[string]string{"bundles/acme.yaml": "kind: EnvironmentProfile\nname: py\nspec: {image: stable, env: {A: b}}\n", "bundles/other.yml": "x: 1\n"}, "two")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cli := CLI{Timeout: 30 * time.Second}
	// A bare token is the password of the conventional user; a user:token pair is used as is.
	for _, auth := range []string{"tok-secret-1", "x-access-token:tok-secret-1"} {
		r := Remote{URL: url, Ref: "main", Auth: auth}
		head, err := cli.Resolve(ctx, r)
		if err != nil || head != sha2 {
			t.Fatalf("resolve with %q: %q %v", auth, head, err)
		}
	}
	r := Remote{URL: url, Ref: "main", Auth: "tok-secret-1"}
	files, err := cli.Files(ctx, r, sha2, []string{"bundles/*.yaml"})
	if err != nil || len(files) != 1 || !strings.Contains(string(files["bundles/acme.yaml"]), "A: b") {
		t.Fatalf("files at head: %v %v", files, err)
	}
	// An earlier commit of the ref: found by deepening the shallow fetch; its content, not the head's.
	files, err = cli.Files(ctx, r, sha1, []string{"bundles/acme.yaml"})
	if err != nil || !strings.Contains(string(files["bundles/acme.yaml"]), "image: stable}") || strings.Contains(string(files["bundles/acme.yaml"]), "A: b") {
		t.Fatalf("files at an earlier commit: %v %v", files, err)
	}
	// Patterns: several, with literal paths; nothing matching is its own error.
	if files, err := cli.Files(ctx, r, sha2, []string{"bundles/other.yml", "README.md"}); err != nil || len(files) != 2 {
		t.Fatalf("literal paths: %v %v", files, err)
	}
	if _, err := cli.Files(ctx, r, sha2, []string{"nothing/*.yaml"}); !errors.Is(err, ErrNoMatch) {
		t.Fatalf("no match: %v", err)
	}
	// A wrong credential: the server's refusal, no file. The token is not in the message.
	bad := Remote{URL: url, Ref: "main", Auth: "wrong"}
	if _, err := cli.Resolve(ctx, bad); err == nil || strings.Contains(err.Error(), "wrong") || !strings.Contains(err.Error(), "refused the credential (HTTP 401)") {
		t.Fatalf("wrong credential: %v", err)
	}
	if _, err := cli.Files(ctx, bad, sha2, []string{"bundles/*.yaml"}); err == nil {
		t.Fatal("files with a wrong credential")
	}
	// No credential at all against a protected repository.
	if _, err := cli.Resolve(ctx, Remote{URL: url, Ref: "main"}); err == nil {
		t.Fatal("no credential against a protected repository")
	}
	// A ref that does not exist; a commit that is not on the ref (another branch's).
	if _, err := cli.Resolve(ctx, Remote{URL: url, Ref: "nope", Auth: "tok-secret-1"}); !errors.Is(err, ErrNoRef) {
		t.Fatalf("missing ref: %v", err)
	}
	if _, err := cli.Files(ctx, r, "0123456789abcdef0123456789abcdef01234567", []string{"bundles/*.yaml"}); !errors.Is(err, ErrNotOnRef) {
		t.Fatalf("a commit not on the ref: %v", err)
	}
	if _, err := cli.Files(ctx, r, "deadbeef", []string{"bundles/*.yaml"}); err == nil {
		t.Fatal("a non-SHA was accepted")
	}
	// Unreachable server.
	if _, err := cli.Resolve(ctx, Remote{URL: "http://127.0.0.1:9/acme/config.git", Ref: "main"}); err == nil {
		t.Fatal("unreachable repository resolved")
	}
}

func TestCLIResolvesTagsToCommitsAndServesPublicRepositories(t *testing.T) {
	g := gittest.New(t, "", "")
	url, work, commit := g.URL, g.Work, func(files map[string]string, msg string) string { return g.Commit(t, files, msg) }
	sha := commit(map[string]string{"b.yaml": "kind: EnvironmentProfile\nname: py\nspec: {image: stable}\n"}, "one")
	ctx := context.Background()
	cli := CLI{}
	if head, err := cli.Resolve(ctx, Remote{URL: url, Ref: "main"}); err != nil || head != sha {
		t.Fatalf("public resolve: %q %v", head, err)
	}
	// An annotated tag resolves to the commit it points at, not to the tag object; a
	// lightweight tag too. Files are read at that commit.
	gittest.Git(t, work, "tag", "-a", "v1", "-m", "release")
	gittest.Git(t, work, "tag", "light")
	gittest.Git(t, work, "push", "-q", "origin", "v1", "light")
	for _, tag := range []string{"v1", "light"} {
		if head, err := cli.Resolve(ctx, Remote{URL: url, Ref: tag}); err != nil || head != sha {
			t.Fatalf("tag %s: %q %v", tag, head, err)
		}
		if files, err := cli.Files(ctx, Remote{URL: url, Ref: tag}, sha, []string{"*.yaml"}); err != nil || len(files) != 1 {
			t.Fatalf("files at tag %s: %v %v", tag, files, err)
		}
	}
	// A branch and a tag of the same name: the branch wins, as git's own resolution does.
	sha2 := commit(map[string]string{"b.yaml": "kind: EnvironmentProfile\nname: py\nspec: {image: stable, env: {X: y}}\n"}, "two")
	gittest.Git(t, work, "tag", "main-tag", sha)
	gittest.Git(t, work, "push", "-q", "origin", "main-tag")
	if head, err := cli.Resolve(ctx, Remote{URL: url, Ref: "main"}); err != nil || head != sha2 {
		t.Fatalf("branch after a second commit: %q %v", head, err)
	}
}

func TestMatches(t *testing.T) {
	cases := []struct {
		name string
		pats []string
		want bool
	}{
		{"bundles/acme.yaml", []string{"bundles/*.yaml"}, true},
		{"bundles/sub/acme.yaml", []string{"bundles/*.yaml"}, false},
		{"bundles/acme.yaml", []string{"bundles/acme.yaml"}, true},
		{"other/acme.yaml", []string{"bundles/*.yaml", "other/acme.yaml"}, true},
		{"x.yaml", []string{"*.yml"}, false},
	}
	for _, c := range cases {
		if got := Matches(c.name, c.pats); got != c.want {
			t.Errorf("Matches(%q, %v) = %v", c.name, c.pats, got)
		}
	}
}
