package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"agent-sandbox/internal/apply"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/plan"
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

	read := func(f string) []byte {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	src, ok, dirty, err := gitSource(file, read(file))
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
	src, ok, dirty, err = gitSource(file, read(file))
	if err != nil || !ok || !dirty || src.Commit != "" || src.Path != "bundles/acme.yaml" || src.Ref != "main" {
		t.Fatalf("dirty file: %v ok=%v dirty=%v %+v", err, ok, dirty, src)
	}
	// `git status` can be made to lie (assume-unchanged, skip-worktree): the decision is made on
	// the bytes, so the modified file still gets no SHA.
	run(t, repo, "update-index", "--assume-unchanged", "--", file)
	if status := run(t, repo, "status", "--porcelain", "--", file); status != "" {
		t.Fatalf("precondition: status should report clean, got %q", status)
	}
	if src, _, dirty, _ := gitSource(file, read(file)); !dirty || src.Commit != "" {
		t.Fatalf("assume-unchanged hid a modification: dirty=%v %+v", dirty, src)
	}
	run(t, repo, "update-index", "--no-assume-unchanged", "--", file)
	// A staged change is not committed either.
	run(t, repo, "add", "--", file)
	if src, _, dirty, _ := gitSource(file, read(file)); !dirty || src.Commit != "" {
		t.Fatalf("staged content attributed to HEAD: dirty=%v %+v", dirty, src)
	}
	// The bytes being applied are what count: the committed bytes, wherever they come from, match.
	if src, _, dirty, _ := gitSource(file, []byte("kind: EnvironmentProfile\nname: py\nspec: {image: stable}\n")); dirty || src.Commit != head {
		t.Fatalf("committed bytes: dirty=%v %+v", dirty, src)
	}
	// A credential in the remote never leaves the client.
	run(t, repo, "remote", "set-url", "origin", "https://x-access-token:ghp_secret123@github.com/acme/platform.git")
	if src, _, _, _ := gitSource(file, read(file)); src.Repo != "https://github.com/acme/platform.git" || strings.Contains(src.Repo, "secret") {
		t.Fatalf("credential in remote: %+v", src)
	}
	// An untracked file: in the repository, but no commit holds it.
	other := filepath.Join(repo, "bundles", "new.yaml")
	if err := os.WriteFile(other, []byte("kind: EnvironmentProfile\nname: go\nspec: {image: stable}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if src, ok, dirty, err := gitSource(other, read(other)); err != nil || !ok || !dirty || src.Commit != "" || src.Path != "" {
		t.Fatalf("untracked file: %v ok=%v dirty=%v %+v", err, ok, dirty, src)
	}
	// Outside a work tree: nothing to record.
	plain := filepath.Join(root, "plain.yaml")
	if err := os.WriteFile(plain, []byte("x: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok, _, err := gitSource(plain, read(plain)); err != nil || ok {
		t.Fatalf("outside a repository: ok=%v %v", ok, err)
	}
	// Explicit flags win over detection.
	merged := mergeSource(bundleSource{Commit: "deadbeef"}, bundleSource{Commit: head, Ref: "main"})
	if merged.Commit != "deadbeef" || merged.Ref != "main" {
		t.Fatalf("merge: %+v", merged)
	}
}

func TestExitCodesDoNotDependOnTheOutputFormat(t *testing.T) {
	valid := plan.Plan{Valid: true}
	if planExitCode(valid) != 0 || planExitCode(plan.Plan{Valid: true, Summary: plan.Summary{Update: 1}}) != 3 || planExitCode(plan.Plan{Valid: false}) != 2 {
		t.Fatal("plan exit codes")
	}
	// A bundle-level error (duplicate documents) is invalid even with every change a noop.
	if planExitCode(plan.Plan{Valid: false, Errors: []string{"documents 1 and 2 both describe …"}}) != 2 {
		t.Fatal("bundle-level errors are failures")
	}
	done := &model.Apply{Status: model.ApplyDone}
	conflict := &model.Apply{Status: model.ApplyConflict}
	running := &model.Apply{Status: model.ApplyRunning}
	cases := []struct {
		rb   apply.Rollback
		want int
	}{
		{apply.Rollback{Plan: &valid, Apply: done}, 0},
		{apply.Rollback{Plan: &valid}, 0}, // dry run of a valid plan
		{apply.Rollback{Plan: &plan.Plan{Valid: false}}, 2},
		{apply.Rollback{Plan: &valid, Apply: conflict}, 3},
		{apply.Rollback{Plan: &valid, Apply: running}, 3},
		{apply.Rollback{}, 2},
	}
	for i, c := range cases {
		if got := rollbackExitCode(c.rb); got != c.want {
			t.Fatalf("case %d: exit %d, want %d", i, got, c.want)
		}
	}
}

// A checkout Git refuses to read (the CI container runs as another user than the one that
// cloned: "detected dubious ownership") is an error, not "no repository": applying with it
// silently would lose the SHA. Git's own test switch makes every repository look foreign.
func TestGitSourceSurfacesACheckoutGitCannotRead(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is required")
	}
	repo := t.TempDir()
	run(t, repo, "init", "-q", "-b", "main")
	file := filepath.Join(repo, "bundle.yaml")
	content := []byte("kind: EnvironmentProfile\nname: py\nspec: {image: stable}\n")
	if err := os.WriteFile(file, content, 0o644); err != nil {
		t.Fatal(err)
	}
	run(t, repo, "add", ".")
	run(t, repo, "commit", "-q", "-m", "bundle")
	head := run(t, repo, "rev-parse", "HEAD")

	// Git's own test switch makes every repository look foreign; the machine's configuration
	// is left out (CI runners mark every directory safe, which is exactly what is under test).
	isolateGitConfig(t)
	t.Setenv("GIT_TEST_ASSUME_DIFFERENT_OWNER", "1")
	if out, err := exec.Command("git", "-C", repo, "rev-parse", "--show-toplevel").CombinedOutput(); err == nil || !strings.Contains(string(out), "dubious ownership") {
		t.Fatalf("precondition: this git does not refuse a foreign-owned checkout under GIT_TEST_ASSUME_DIFFERENT_OWNER: %v %s", err, out)
	}
	src, ok, dirty, err := gitSource(file, content)
	if err == nil || !strings.Contains(err.Error(), "dubious ownership") || ok || dirty || src.Commit != "" {
		t.Fatalf("a foreign-owned checkout must be an error, not a plain file: ok=%v dirty=%v err=%v %+v", ok, dirty, err, src)
	}
	if strings.Contains(err.Error(), "\n") {
		t.Errorf("one line of git's message is enough: %q", err)
	}
	// What the sandboxctl image configures (safe.directory for every directory) makes the same
	// checkout readable again, and the SHA is recorded.
	if err := os.WriteFile(os.Getenv("GIT_CONFIG_GLOBAL"), []byte("[safe]\n\tdirectory = *\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if src, ok, dirty, err := gitSource(file, content); err != nil || !ok || dirty || src.Commit != head {
		t.Fatalf("with safe.directory: ok=%v dirty=%v err=%v %+v", ok, dirty, err, src)
	}
	// Any other Git failure is surfaced too (a corrupt configuration here).
	t.Setenv("GIT_TEST_ASSUME_DIFFERENT_OWNER", "")
	if err := os.WriteFile(filepath.Join(repo, ".git", "config"), []byte("[core\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok, _, err := gitSource(file, content); err == nil || ok {
		t.Fatalf("a corrupt repository must be an error: ok=%v err=%v", ok, err)
	}
}

// isolateGitConfig hides the machine's system and global Git configuration from the test
// (a safe.directory set there would mask the ownership check), returning the empty global
// file so a test can write its own.
func isolateGitConfig(t *testing.T) string {
	t.Helper()
	global := filepath.Join(t.TempDir(), "gitconfig")
	if err := os.WriteFile(global, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_CONFIG_GLOBAL", global)
	return global
}
