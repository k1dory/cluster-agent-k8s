package ci

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// stub puts an executable with the given shell body first on PATH and returns that PATH.
func stub(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/usr/bin/env bash\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
}

// module writes a small Go module: one formatted file, and, under cacheDir, an unformatted
// one that stands for a module cache kept inside the tree (GitLab's cached GOMODCACHE).
func module(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"go.mod":                      "module contractcheck\n\ngo 1.26\n",
		"ok.go":                       "package contractcheck\n\n// Fine is formatted.\nfunc Fine() int { return 1 }\n",
		".go-mod-cache/x/y/junk.go":   "package junk\nfunc  Ugly( ) {   }\n",
		".ci/bin/caddy-2.0/vendor.go": "package vendored\nfunc   AlsoUgly()  {}\n",
	}
	for name, body := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func runScript(t *testing.T, script string, env map[string]string, path string) (string, error) {
	t.Helper()
	cmd := exec.Command(filepath.Join(repoRoot(t), script))
	cmd.Env = append(os.Environ(), "PATH="+path+string(os.PathListSeparator)+os.Getenv("PATH"))
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// gofmt is run over the module's own Go files as `go list` names them: a module cache or a
// tool directory inside the tree is never formatted, so a clean project stays clean on a
// runner that caches dependencies under the project directory.
func TestVetIgnoresAModuleCacheInsideTheTree(t *testing.T) {
	mod := module(t)
	out, err := runScript(t, "hack/ci/vet.sh", map[string]string{"CI_ROOT": mod}, t.TempDir())
	if err != nil || !strings.HasSuffix(strings.TrimSpace(out), "ci: vet: ok") {
		t.Fatalf("a clean module with a cache inside the tree must pass: %v\n%s", err, out)
	}
	// And a file of the module's own that is not formatted still fails, named.
	if err := os.WriteFile(filepath.Join(mod, "bad.go"), []byte("package contractcheck\nfunc   Bad()  {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err = runScript(t, "hack/ci/vet.sh", map[string]string{"CI_ROOT": mod}, t.TempDir())
	if err == nil || strings.Contains(out, "ci: vet: ok") || !strings.Contains(out, "bad.go") {
		t.Fatalf("an unformatted file of the module must fail and be named: %v\n%s", err, out)
	}
}

// A formatter that fails without printing anything is a failed check, never a clean tree.
func TestVetFailsWhenGofmtFails(t *testing.T) {
	bin := t.TempDir()
	stub(t, bin, "gofmt", "exit 3\n")
	out, err := runScript(t, "hack/ci/vet.sh", map[string]string{"CI_ROOT": module(t)}, bin)
	if err == nil || strings.Contains(out, "ci: vet: ok") || !strings.Contains(out, "gofmt failed") {
		t.Fatalf("a failing gofmt must fail the group: %v\n%s", err, out)
	}
}

// The Git-adapter end to end hands the daemon no private temporary path of the job (its work
// directory is inside the checkout) and refuses, with the reason, a daemon that does not see
// this host's files; what it does reach, it reaches at the daemon's bridge address, never at
// a localhost that in a job container is the container's own.
func TestE2ERefusesADaemonThatSeesNoFilesAndUsesNoPrivateTmp(t *testing.T) {
	root := repoRoot(t)
	bin := t.TempDir()
	log := filepath.Join(t.TempDir(), "docker.log")
	// A daemon elsewhere: every command succeeds, but a bind-mounted file is not there.
	stub(t, bin, "docker", `printf '%s\n' "$*" >> "`+log+`"
case "$1" in
  run) for a in "$@"; do [ "$a" = /probe ] && exit 1; done; echo id ;;
  *) exit 0 ;;
esac
`)
	out, err := runScript(t, "hack/e2e-git-adapter.sh", map[string]string{"DOCKER_HOST": "tcp://docker:2375"}, bin)
	if err == nil || !strings.Contains(out, "does not see this host's files") {
		t.Fatalf("a daemon that sees no files must be refused with the reason: %v\n%s", err, out)
	}
	calls, _ := os.ReadFile(log)
	for _, line := range strings.Split(string(calls), "\n") {
		fields := strings.Fields(line)
		for i, f := range fields {
			if f == "-v" && i+1 < len(fields) {
				src := fields[i+1][:strings.Index(fields[i+1], ":")]
				if !strings.HasPrefix(src, root+string(os.PathSeparator)) {
					t.Errorf("a bind mount from outside the checkout was handed to the daemon: %s", fields[i+1])
				}
				if strings.HasPrefix(src, os.TempDir()+string(os.PathSeparator)) {
					t.Errorf("a bind mount from the private temporary directory: %s", fields[i+1])
				}
			}
		}
	}
	if left, _ := filepath.Glob(filepath.Join(root, ".ci", "e2e.*")); len(left) != 0 {
		t.Errorf("the work directory was not cleaned up: %v", left)
	}
	script, err := os.ReadFile(filepath.Join(root, "hack/e2e-git-adapter.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"http://127.0.0.1:$port", "http://localhost", "mktemp -d)"} {
		if strings.Contains(string(script), bad) {
			t.Errorf("the script still uses %q", bad)
		}
	}
	if !strings.Contains(string(script), `api="http://$bridge:$port"`) {
		t.Error("the script must reach the API at the daemon's bridge address")
	}
}

// The images group moves the checkout to the daemon through the API (docker cp), so a daemon
// on another host (a docker-in-docker service) gets the files too.
func TestImagesMoveTheCheckoutThroughTheAPI(t *testing.T) {
	script, err := os.ReadFile(filepath.Join(repoRoot(t), "hack/ci/images.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(script), `-v "$PWD`) || strings.Contains(string(script), "-v \"$here") {
		t.Error("images.sh bind-mounts the job's files")
	}
	if !strings.Contains(string(script), "docker cp . ") {
		t.Error("images.sh must copy the checkout with docker cp")
	}
}
