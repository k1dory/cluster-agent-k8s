package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// ctlChild runs the CLI in a child process (its os.Exit calls are the outcome under test) and
// returns stdout, stderr and the exit code. dir is the working directory; env is added.
func ctlChild(t *testing.T, dir, base, token string, env []string, args ...string) (string, string, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], append([]string{"-test.run=^TestAdapterCLIChild$", "--"}, args...)...)
	cmd.Dir = dir
	cmd.Env = append(append(os.Environ(), "SANDBOX_ADAPTER_CHILD=1", "SANDBOX_ADAPTER_URL="+base, "SANDBOX_ADAPTER_TOKEN="+token), env...)
	var out, errOut strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	code := 0
	var exited *exec.ExitError
	if errors.As(err, &exited) {
		code = exited.ExitCode()
	} else if err != nil {
		t.Fatalf("run CLI: %v", err)
	}
	if ctx.Err() != nil {
		t.Fatal("CLI did not finish")
	}
	return out.String(), errOut.String(), code
}

func TestAdapterCLIChild(t *testing.T) {
	if os.Getenv("SANDBOX_ADAPTER_CHILD") != "1" {
		t.Skip("child process entry point")
	}
	var args []string
	for i, arg := range os.Args {
		if arg == "--" {
			args = os.Args[i+1:]
			break
		}
	}
	c := &cli{base: os.Getenv("SANDBOX_ADAPTER_URL"), token: os.Getenv("SANDBOX_ADAPTER_TOKEN"), http: &http.Client{Timeout: 5 * time.Second}}
	if err := c.run(args[0], args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "sandboxctl:", err)
		os.Exit(1)
	}
	os.Exit(0)
}

// With -markdown, a command that produced no result still prints a marker block: the pipeline
// replaces its comment with the failure instead of leaving the previous push's plan there.
func TestAdapterMarkdownOnFailurePaths(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is required")
	}
	repo := t.TempDir()
	run(t, repo, "init", "-q", "-b", "main")
	if err := os.MkdirAll(filepath.Join(repo, "bundles"), 0o755); err != nil {
		t.Fatal(err)
	}
	bundle := "kind: EnvironmentProfile\nname: py\nspec: {image: stable}\n"
	if err := os.WriteFile(filepath.Join(repo, "bundles", "acme.yaml"), []byte(bundle), 0o644); err != nil {
		t.Fatal(err)
	}
	run(t, repo, "add", ".")
	run(t, repo, "commit", "-q", "-m", "bundle")

	var mu sync.Mutex
	var planResponse, applyResponse string
	var planStatus, applyStatus int
	var lastApplyBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/plan":
			w.WriteHeader(planStatus)
			fmt.Fprint(w, planResponse)
		case "/v1/drift":
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"unknown token","code":"unauthorized"}`)
		case "/v1/apply":
			buf := make([]byte, 1<<16)
			n, _ := r.Body.Read(buf)
			lastApplyBody = string(buf[:n])
			w.WriteHeader(applyStatus)
			fmt.Fprint(w, applyResponse)
		default:
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error":"no such route"}`)
		}
	}))
	defer srv.Close()
	set := func(ps int, pr string, as int, ar string) {
		mu.Lock()
		defer mu.Unlock()
		planStatus, planResponse, applyStatus, applyResponse = ps, pr, as, ar
	}

	// The platform refuses the token: plan, apply and drift print the failure under the marker.
	set(401, `{"error":"unknown token","code":"unauthorized"}`, 401, `{"error":"unknown token"}`)
	for _, args := range [][]string{{"plan", "-f", "bundles/acme.yaml", "-markdown"}, {"apply", "-f", "bundles/acme.yaml", "-markdown"}, {"drift", "-markdown"}, {"drift", "-f", "bundles/acme.yaml", "-markdown"}} {
		out, errOut, code := ctlChild(t, repo, srv.URL, "bad", nil, args...)
		if code != 1 || !strings.HasPrefix(out, Marker+"\n### ") || !strings.Contains(out, "❌ error") || !strings.Contains(out, "unknown token") || !strings.Contains(errOut, "unknown token") {
			t.Errorf("%v: exit %d\nstdout:\n%s\nstderr:\n%s", args, code, out, errOut)
		}
	}
	// Without -markdown nothing but the error is printed (a terminal, not a comment).
	if out, _, code := ctlChild(t, repo, srv.URL, "bad", nil, "apply", "-f", "bundles/acme.yaml"); code != 1 || out != "" {
		t.Errorf("plain apply failure: exit %d stdout %q", code, out)
	}
	// An invalid plan on apply renders the plan in the requested format (nothing was written)
	// and exits 2; the apply endpoint is never called.
	set(200, `{"valid":false,"summary":{"invalid":1},"changes":[{"kind":"EnvironmentProfile","tenant":"acme","name":"py","action":"invalid","errors":["image nope|unknown"]}]}`, 500, `{"error":"must not be called"}`)
	out, _, code := ctlChild(t, repo, srv.URL, "t", nil, "apply", "-f", "bundles/acme.yaml", "-markdown")
	if code != 2 || !strings.HasPrefix(out, Marker+"\n### Plan ❌ invalid · `bundles/acme.yaml`") || !strings.Contains(out, "image nope\\|unknown") {
		t.Errorf("invalid apply -markdown: exit %d\n%s", code, out)
	}
	if out, _, code := ctlChild(t, repo, srv.URL, "t", nil, "apply", "-f", "bundles/acme.yaml", "-json"); code != 2 || !strings.Contains(out, `"valid": false`) {
		t.Errorf("invalid apply -json: exit %d\n%s", code, out)
	}
	mu.Lock()
	if lastApplyBody != "" {
		t.Errorf("an invalid plan reached /v1/apply: %s", lastApplyBody)
	}
	mu.Unlock()

	// -require-commit: a clean checkout applies with the SHA and the key; a modified file, a
	// checkout Git cannot read, a file outside a repository and -no-git fail before any request.
	head := run(t, repo, "rev-parse", "HEAD")
	set(200, `{"valid":true,"plan":"fp1","bundle":"b1","summary":{"create":1},"changes":[]}`, 200, `{"id":"apply_1","status":"done","steps":[]}`)
	out, _, code = ctlChild(t, repo, srv.URL, "t", nil, "apply", "-f", "bundles/acme.yaml", "-key", "bundles/acme.yaml@"+head, "-require-commit", "-ref", "main", "-markdown")
	if code != 0 || !strings.Contains(out, "### Apply ✅ done") {
		t.Fatalf("clean apply: exit %d\n%s", code, out)
	}
	mu.Lock()
	body := lastApplyBody
	lastApplyBody = ""
	mu.Unlock()
	for _, want := range []string{`"key":"bundles/acme.yaml@` + head + `"`, `"commit":"` + head + `"`, `"path":"bundles/acme.yaml"`, `"ref":"main"`, `"plan":"fp1"`} {
		if !strings.Contains(body, want) {
			t.Errorf("apply body lacks %s: %s", want, body)
		}
	}
	if err := os.WriteFile(filepath.Join(repo, "bundles", "acme.yaml"), []byte(bundle+"# edited\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		env  []string
		args []string
		want string
	}{
		{"modified", nil, []string{"apply", "-f", "bundles/acme.yaml", "-require-commit", "-markdown"}, "not what HEAD holds"},
		{"foreign_owner", []string{"GIT_TEST_ASSUME_DIFFERENT_OWNER=1", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + isolateGitConfig(t)}, []string{"apply", "-f", "bundles/acme.yaml", "-markdown"}, "dubious ownership"},
		{"no_git", nil, []string{"apply", "-f", "bundles/acme.yaml", "-require-commit", "-no-git", "-markdown"}, "-no-git records no source"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mu.Lock()
			lastApplyBody = ""
			mu.Unlock()
			out, errOut, code := ctlChild(t, repo, srv.URL, "t", tc.env, tc.args...)
			if code != 1 || !strings.Contains(errOut, tc.want) || !strings.HasPrefix(out, Marker+"\n### Apply ❌ error") {
				t.Errorf("exit %d\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
			}
			mu.Lock()
			defer mu.Unlock()
			if lastApplyBody != "" {
				t.Errorf("an apply without a verifiable SHA reached the platform: %s", lastApplyBody)
			}
		})
	}
	// Outside any repository (the file is a plain copy): -require-commit refuses, -commit satisfies it.
	plain := t.TempDir()
	if err := os.WriteFile(filepath.Join(plain, "b.yaml"), []byte(bundle), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, errOut, code := ctlChild(t, plain, srv.URL, "t", nil, "apply", "-f", "b.yaml", "-require-commit"); code != 1 || !strings.Contains(errOut, "not in a Git work tree") {
		t.Errorf("outside a repository: exit %d %s", code, errOut)
	}
	if _, errOut, code := ctlChild(t, plain, srv.URL, "t", nil, "apply", "-f", "b.yaml", "-require-commit", "-commit", head); code != 0 {
		t.Errorf("explicit -commit: exit %d %s", code, errOut)
	}
}

// The templates: parsed as YAML, and their shell run against a fake docker / sandboxctl so the
// exit-code handling the review found wanting is checked where it lives.
func readTemplate(t *testing.T, path string) (string, map[string]any) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return string(raw), doc
}

func githubStep(t *testing.T, doc map[string]any, job, name string) string {
	t.Helper()
	jobs := doc["jobs"].(map[string]any)
	for _, s := range jobs[job].(map[string]any)["steps"].([]any) {
		st := s.(map[string]any)
		if n, _ := st["name"].(string); n == name {
			if st["shell"] != "bash" {
				t.Errorf("%s/%s: run steps use bash explicitly (pipefail, consistent exit handling)", job, name)
			}
			return st["run"].(string)
		}
	}
	t.Fatalf("no step %q in job %q", name, job)
	return ""
}

// fakeDocker stands in for `docker run … IMAGE plan|apply|drift …`: it finds the bundle after -f
// and behaves per its name; apply logs its arguments; drift reports drift.
const fakeDocker = `#!/bin/bash
f=""; prev=""; sub=""
for a in "$@"; do
  [ "$prev" = "-f" ] && f="$a"
  case "$a" in plan|apply|drift) [ -z "$sub" ] && sub="$a";; esac
  prev="$a"
done
echo "$*" >> "$FAKE_LOG"
case "$sub" in
  drift) printf '<!-- agent-sandbox -->\n### Drift ⚠️ 1 of 3 managed items\n'; exit 3;;
esac
case "$f" in
  *broken*) echo "docker: image not found" >&2; exit 127;;
  *bad*) printf '<!-- agent-sandbox -->\n### %s ❌ invalid · %s\n' "$sub" "$f"; exit 2;;
  *) printf '<!-- agent-sandbox -->\n### %s ✅ ok · %s\n' "$sub" "$f"; exit 0;;
esac
`

func shellEnv(t *testing.T, work string) (env []string, summary, log string) {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(fakeDocker), 0o755); err != nil {
		t.Fatal(err)
	}
	// GitLab's job runs the binary at /sandboxctl; the test rewrites that path to the fake.
	if err := os.WriteFile(filepath.Join(bin, "sandboxctl"), []byte(fakeDocker), 0o755); err != nil {
		t.Fatal(err)
	}
	summary, log = filepath.Join(work, "summary.md"), filepath.Join(work, "args.log")
	env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "GITHUB_STEP_SUMMARY="+summary, "FAKE_LOG="+log,
		"SANDBOXCTL_IMAGE=img", "SANDBOX_TENANT=", "GITHUB_REF_NAME=main", "GITHUB_SHA=abc123", "GITHUB_SERVER_URL=https://github.com", "GITHUB_REPOSITORY=acme/config",
		"CI_COMMIT_BRANCH=main", "CI_COMMIT_SHA=abc123", "CI_PROJECT_URL=https://gitlab.example/acme/config", "GITLAB_TOKEN=", "SANDBOXD_URL=http://x", "SANDBOXD_TOKEN=t")
	return env, summary, log
}

func runScript(t *testing.T, shell, work, script string, env []string) (string, int) {
	t.Helper()
	cmd := exec.Command(shell, "-c", script)
	cmd.Dir, cmd.Env = work, env
	out, err := cmd.CombinedOutput()
	code := 0
	var exited *exec.ExitError
	if errors.As(err, &exited) {
		code = exited.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return string(out), code
}

func bundlesDir(t *testing.T) string {
	t.Helper()
	work := t.TempDir()
	if err := os.MkdirAll(filepath.Join(work, "bundles"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"bad.yaml", "broken.yaml", "good.yaml"} {
		if err := os.WriteFile(filepath.Join(work, "bundles", n), []byte("x: 1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return work
}

func TestGitHubTemplateFailsOnEveryNonZeroExitAndKeepsEveryBlock(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is required")
	}
	_, doc := readTemplate(t, filepath.Join("..", "..", "deploy", "git", "github", "sandbox-config.yml"))
	work := bundlesDir(t)
	env, summary, log := shellEnv(t, work)

	// plan: bad (2), broken (127: the container did not run), good (0). The check fails, and the
	// comment has a block for every bundle, the broken one written by the loop itself.
	out, code := runScript(t, "bash", work, githubStep(t, doc, "plan", "plan every bundle"), env)
	if code == 0 {
		t.Fatalf("plan step passed although one container exited 127:\n%s", out)
	}
	plans, _ := os.ReadFile(filepath.Join(work, "plans.md"))
	if n := strings.Count(string(plans), Marker); n != 3 {
		t.Errorf("plans.md has %d blocks, want one per bundle:\n%s", n, plans)
	}
	if !strings.Contains(string(plans), "bundles/broken.yaml") || !strings.Contains(string(plans), "exited 127") {
		t.Errorf("the bundle whose container did not run has no block:\n%s", plans)
	}
	sum, _ := os.ReadFile(summary)
	if string(sum) != string(plans) {
		t.Error("the job summary differs from the comment")
	}
	// Only the invalid one: exit 2 (the comment says why).
	_ = os.Remove(filepath.Join(work, "bundles", "broken.yaml"))
	if _, code := runScript(t, "bash", work, githubStep(t, doc, "plan", "plan every bundle"), env); code != 2 {
		t.Errorf("plan with an invalid bundle: exit %d, want 2", code)
	}
	_ = os.Remove(filepath.Join(work, "bundles", "bad.yaml"))
	if out, code := runScript(t, "bash", work, githubStep(t, doc, "plan", "plan every bundle"), env); code != 0 {
		t.Errorf("plan with valid bundles: exit %d\n%s", code, out)
	}

	// apply: a stable key (bundle at this commit) and -require-commit on every call; a failing
	// container fails the job and leaves a block in the summary.
	_ = os.WriteFile(filepath.Join(work, "bundles", "broken.yaml"), []byte("x: 1\n"), 0o644)
	_ = os.Remove(log)
	_ = os.Remove(summary)
	out, code = runScript(t, "bash", work, githubStep(t, doc, "apply", "apply every bundle with this commit as the source"), env)
	if code != 127 {
		t.Errorf("apply with a container that did not run: exit %d, want 127\n%s", code, out)
	}
	args, _ := os.ReadFile(log)
	for _, want := range []string{"apply -f bundles/good.yaml", "-key bundles/good.yaml@abc123", "-require-commit", "-ref main", "-repo https://github.com/acme/config", "-markdown"} {
		if !strings.Contains(string(args), want) {
			t.Errorf("apply arguments lack %q:\n%s", want, args)
		}
	}
	sum, _ = os.ReadFile(summary)
	if strings.Count(string(sum), Marker) != 2 || !strings.Contains(string(sum), "exited 127") {
		t.Errorf("apply summary:\n%s", sum)
	}

	// drift: the report reaches the summary and exit 3 is the step's (no pipe to hide it).
	_ = os.Remove(summary)
	out, code = runScript(t, "bash", work, githubStep(t, doc, "drift", "what moved outside apply"), env)
	sum, _ = os.ReadFile(summary)
	if code != 3 || !strings.Contains(string(sum), "Drift ⚠️") || !strings.Contains(out, "Drift ⚠️") {
		t.Errorf("drift: exit %d\nout:\n%s\nsummary:\n%s", code, out, sum)
	}
	if strings.Contains(githubStep(t, doc, "drift", "what moved outside apply"), "| tee") {
		t.Error("tee would hide sandboxctl's exit code")
	}
}

func gitlabScript(t *testing.T, doc map[string]any, job string) string {
	t.Helper()
	var lines []string
	for _, l := range doc[job].(map[string]any)["script"].([]any) {
		lines = append(lines, l.(string))
	}
	// GitLab concatenates the lines into one script and runs it with set -e (sh in this image).
	return "set -e\n" + strings.ReplaceAll(strings.Join(lines, "\n"), "/sandboxctl", "sandboxctl")
}

func TestGitLabTemplatePostsTheNoteOnFailureAndNeverAppliesOnASchedule(t *testing.T) {
	raw, doc := readTemplate(t, filepath.Join("..", "..", "deploy", "git", "gitlab", ".gitlab-ci.yml"))
	rules := doc["apply"].(map[string]any)["rules"].([]any)
	cond := rules[0].(map[string]any)["if"].(string)
	if !strings.Contains(cond, `$CI_PIPELINE_SOURCE == "push"`) || !strings.Contains(cond, "$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH") {
		t.Errorf("apply must run on a push to the default branch only (changes: is true on a schedule): %q", cond)
	}
	if !strings.Contains(raw, `-key "$f@$CI_COMMIT_SHA" -require-commit`) {
		t.Error("apply must use a stable key and require the commit SHA")
	}
	work := bundlesDir(t)
	env, _, log := shellEnv(t, work)
	// plan: the loop survives an invalid bundle and a failed run; plans.md holds every block, the
	// note step runs (no token here: skipped), and the job ends with the failure code.
	out, code := runScript(t, "sh", work, gitlabScript(t, doc, "plan"), env)
	plans, _ := os.ReadFile(filepath.Join(work, "plans.md"))
	if code == 0 || strings.Count(string(plans), Marker) != 2 || !strings.Contains(out, "✅ ok · bundles/good.yaml") {
		t.Errorf("plan: exit %d\nout:\n%s\nplans.md:\n%s", code, out, plans)
	}
	_ = os.Remove(filepath.Join(work, "bundles", "broken.yaml"))
	if _, code := runScript(t, "sh", work, gitlabScript(t, doc, "plan"), env); code != 2 {
		t.Errorf("plan with an invalid bundle: exit %d, want 2", code)
	}
	// apply: every bundle is tried, the arguments carry the key and -require-commit.
	_ = os.Remove(log)
	if _, code := runScript(t, "sh", work, gitlabScript(t, doc, "apply"), env); code != 2 {
		t.Errorf("apply with an invalid bundle: exit %d, want 2", code)
	}
	args, _ := os.ReadFile(log)
	if !strings.Contains(string(args), "apply -f bundles/good.yaml") || !strings.Contains(string(args), "-key bundles/good.yaml@abc123 -require-commit") {
		t.Errorf("apply arguments:\n%s", args)
	}
	// drift: exit 3 reaches the job.
	if out, code := runScript(t, "sh", work, gitlabScript(t, doc, "drift"), env); code != 3 || !strings.Contains(out, "Drift ⚠️") {
		t.Errorf("drift: exit %d\n%s", code, out)
	}
}
