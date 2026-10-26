package ci_test

import (
	"context"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// These tests run the checked-in commands with inert stand-ins for Go, Docker,
// curl and Python where needed. They never build images or contact a service.
func reviewCIFixture(t *testing.T) (project, bin string) {
	t.Helper()
	source, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	project, bin = filepath.Join(root, "project"), filepath.Join(root, "bin")
	reviewCIWrite(t, filepath.Join(project, "owned.go"), "package fixture\n\nconst Value = 1\n", 0600)
	for _, file := range []string{"Makefile", ".gitlab-ci.yml", "go.mod"} {
		reviewCICopy(t, filepath.Join(source, file), filepath.Join(project, file))
	}
	if err := filepath.WalkDir(filepath.Join(source, "hack"), func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || strings.HasSuffix(path, ".go") {
			return nil
		}
		rel, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		reviewCICopy(t, path, filepath.Join(project, rel))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	reviewCIWrite(t, filepath.Join(bin, "go"), "#!/bin/sh\nif [ \"$1\" = list ]; then printf '%s/owned.go\\n' \"$PWD\"; fi\nexit 0\n", 0700)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+filepath.Join(runtime.GOROOT(), "bin")+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("CI_PROJECT_DIR", project)
	t.Setenv("CI_BIN", filepath.Join(root, "tools"))
	privateTmp := filepath.Join(root, "job-private-tmp")
	if err := os.MkdirAll(privateTmp, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", privateTmp)
	for _, args := range [][]string{{"init", "-q"}, {"add", "owned.go", "Makefile", "hack", "go.mod", ".gitlab-ci.yml"}} {
		cmd := exec.Command("git", args...)
		cmd.Dir = project
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("fixture git %v: %v\n%s", args, err, out)
		}
	}
	return project, bin
}

func reviewCIWrite(t *testing.T, path, contents string, mode fs.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), mode); err != nil {
		t.Fatal(err)
	}
}

func reviewCICopy(t *testing.T, from, to string) {
	t.Helper()
	raw, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(from)
	if err != nil {
		t.Fatal(err)
	}
	reviewCIWrite(t, to, string(raw), info.Mode().Perm())
}

func reviewCIRun(t *testing.T, project string, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "make", append([]string{"--no-print-directory"}, args...)...)
	cmd.Dir = project
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("fixture timed out: %v\n%s", ctx.Err(), out)
	}
	return string(out), err
}

func reviewGitLabCI(t *testing.T, project string) map[string]struct {
	Variables map[string]string `yaml:"variables"`
} {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(project, ".gitlab-ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	// Only the variables sections of job-like nodes are needed below.
	var nodes map[string]yaml.Node
	if err := yaml.Unmarshal(raw, &nodes); err != nil {
		t.Fatal(err)
	}
	out := make(map[string]struct {
		Variables map[string]string `yaml:"variables"`
	})
	for _, name := range []string{".docker-job"} {
		var job struct {
			Variables map[string]string `yaml:"variables"`
		}
		node := nodes[name]
		if err := node.Decode(&job); err != nil {
			t.Fatal(err)
		}
		out[name] = job
	}
	var vars map[string]string
	node := nodes["variables"]
	if err := node.Decode(&vars); err != nil {
		t.Fatal(err)
	}
	out["global"] = struct {
		Variables map[string]string `yaml:"variables"`
	}{Variables: vars}
	return out
}

func TestReviewCIVetIgnoresGitLabDependencyCache(t *testing.T) {
	project, _ := reviewCIFixture(t)
	cache := reviewGitLabCI(t, project)["global"].Variables["GOMODCACHE"]
	if cache == "" {
		cache = filepath.Join(t.TempDir(), "modules")
	} else {
		cache = os.ExpandEnv(cache)
	}
	t.Setenv("GOMODCACHE", cache)
	reviewCIWrite(t, filepath.Join(cache, "example.com", "fixture@v1.0.0", "upstream.go"), "package dependency;var Value=1\n", 0600)
	if out, err := reviewCIRun(t, project, "ci-vet"); err != nil {
		t.Errorf("clean project failed because the GitLab module cache was formatted as project code: %v\n%s", err, out)
	}
	reviewCIWrite(t, filepath.Join(project, "owned.go"), "package fixture;const Value=1\n", 0600)
	if out, err := reviewCIRun(t, project, "ci-vet"); err == nil {
		t.Errorf("an unformatted project file must still fail ci-vet:\n%s", out)
	}
}

func TestReviewCIVetPropagatesFormatterFailure(t *testing.T) {
	project, bin := reviewCIFixture(t)
	reviewCIWrite(t, filepath.Join(bin, "gofmt"), "#!/bin/sh\necho 'fixture: formatter could not read input' >&2\nexit 23\n", 0700)
	if out, err := reviewCIRun(t, project, "ci-vet"); err == nil {
		t.Fatalf("ci-vet reported success after its formatter failed:\n%s", out)
	}
}

// GitLab's Docker executor puts the daemon in a separate service container.
// This command-capture fixture checks the launch boundary, not a live runner:
// job-private /tmp is unavailable to that daemon, and its host network is not
// the job container's loopback network.
func TestReviewGitLabE2ERespectsSeparateDockerDaemon(t *testing.T) {
	project, bin := reviewCIFixture(t)
	raw, err := os.ReadFile(filepath.Join(project, ".gitlab-ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	// Only decode this job: top-level variables and stages have other shapes.
	var nodes map[string]yaml.Node
	if err := yaml.Unmarshal(raw, &nodes); err != nil {
		t.Fatal(err)
	}
	var job struct {
		Extends string `yaml:"extends"`
	}
	node := nodes["git-adapter-e2e"]
	if err := node.Decode(&job); err != nil {
		t.Fatal(err)
	}
	if job.Extends != ".docker-job" {
		t.Skip("GitLab E2E no longer inherits the separate Docker service; the new docker-host runner needs live acceptance")
	}
	daemon := reviewGitLabCI(t, project)[".docker-job"].Variables["DOCKER_HOST"]
	if !strings.HasPrefix(daemon, "tcp://docker:") {
		t.Skip("GitLab adapter no longer selects a separate Docker service; validate its replacement on a runner")
	}
	t.Setenv("DOCKER_HOST", daemon)
	dockerLog, curlLog := filepath.Join(t.TempDir(), "docker-args"), filepath.Join(t.TempDir(), "curl-args")
	t.Setenv("REVIEW_DOCKER_LOG", dockerLog)
	t.Setenv("REVIEW_CURL_LOG", curlLog)
	reviewCIWrite(t, filepath.Join(bin, "docker"), "#!/bin/sh\nprintf '%s\\n' \"$@\" >> \"$REVIEW_DOCKER_LOG\"\nexit 0\n", 0700)
	reviewCIWrite(t, filepath.Join(bin, "curl"), "#!/bin/sh\nif [ ! -f \"$REVIEW_CURL_LOG\" ]; then printf '%s\\n' \"$@\" > \"$REVIEW_CURL_LOG\"; fi\nexit 1\n", 0700)
	reviewCIWrite(t, filepath.Join(bin, "python3"), "#!/bin/sh\nexit 0\n", 0700)
	reviewCIWrite(t, filepath.Join(bin, "sleep"), "#!/bin/sh\nexit 0\n", 0700)
	_, _ = reviewCIRun(t, project, "ci-e2e-git") // stop at the inert health check
	dockerArgs, err := os.ReadFile(dockerLog)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(dockerArgs), "sandboxd-e2e") {
		t.Fatalf("fixture did not reach the control-plane launch:\n%s", dockerArgs)
	}
	for _, arg := range strings.Split(string(dockerArgs), "\n") {
		if strings.HasPrefix(arg, os.Getenv("TMPDIR")+string(filepath.Separator)) && strings.Contains(arg, ":") {
			t.Errorf("separate Docker daemon cannot bind a file in the job's private temporary directory: %s", arg)
		}
	}
	curlArgs, err := os.ReadFile(curlLog)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(dockerArgs), "--network\nhost\n") && strings.Contains(string(curlArgs), "http://127.0.0.1:") {
		t.Errorf("health check addresses the job's loopback while the control plane uses the Docker service's host network:\n%s", curlArgs)
	}
}
