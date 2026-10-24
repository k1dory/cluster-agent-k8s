package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func run(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func TestGitSourceNamesOnlyCommittedContent(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is required")
	}
	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	if err := os.MkdirAll(filepath.Join(repo, "bundles"), 0o755); err != nil {
		t.Fatal(err)
	}
	run(t, repo, "init", "-q", "-b", "main")
	run(t, repo, "remote", "add", "origin", "git@example.com:acme/platform.git")
	file := filepath.Join(repo, "bundles", "acme.yaml")
	if err := os.WriteFile(file, []byte("kind: EnvironmentProfile\nname: py\nspec: {image: stable}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run(t, repo, "add", ".")
	run(t, repo, "commit", "-q", "-m", "bundle")
	head := run(t, repo, "rev-parse", "HEAD")

	src, ok, dirty, err := gitSource(file)
	if err != nil || !ok || dirty {
		t.Fatalf("clean file: %v ok=%v dirty=%v", err, ok, dirty)
	}
	if src.Commit != head || src.Ref != "main" || src.Repo != "git@example.com:acme/platform.git" || src.Path != "bundles/acme.yaml" {
		t.Fatalf("source: %+v", src)
	}
	// A modified file is applied without a SHA: the commit does not hold that content.
	if err := os.WriteFile(file, []byte("kind: EnvironmentProfile\nname: py\nspec: {image: canary}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	src, ok, dirty, err = gitSource(file)
	if err != nil || !ok || !dirty || src.Commit != "" || src.Path != "bundles/acme.yaml" || src.Ref != "main" {
		t.Fatalf("dirty file: %v ok=%v dirty=%v %+v", err, ok, dirty, src)
	}
	// An untracked file: in the repository, but no commit holds it.
	other := filepath.Join(repo, "bundles", "new.yaml")
	if err := os.WriteFile(other, []byte("kind: EnvironmentProfile\nname: go\nspec: {image: stable}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if src, ok, dirty, err := gitSource(other); err != nil || !ok || !dirty || src.Commit != "" || src.Path != "" {
		t.Fatalf("untracked file: %v ok=%v dirty=%v %+v", err, ok, dirty, src)
	}
	// Outside a work tree: nothing to record.
	plain := filepath.Join(root, "plain.yaml")
	if err := os.WriteFile(plain, []byte("x: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok, _, err := gitSource(plain); err != nil || ok {
		t.Fatalf("outside a repository: ok=%v %v", ok, err)
	}
	// Explicit flags win over detection.
	merged := mergeSource(bundleSource{Commit: "deadbeef"}, bundleSource{Commit: head, Ref: "main"})
	if merged.Commit != "deadbeef" || merged.Ref != "main" {
		t.Fatalf("merge: %+v", merged)
	}
}
