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

// The image archives the scan exports (a few GiB each) are removed however the check ends: a
// failing verdict exits through ci_die, and the exit trap must still clean the directory.
func TestImagesRemoveTheExportedArchivesWhenTheVerdictFails(t *testing.T) {
	bin := t.TempDir()
	tmp := t.TempDir()
	// A docker that builds nothing but records an id per build, exports an "archive", and
	// answers every other call; a trivy that passes the report and fails the verdict.
	stub(t, bin, "docker", `case "$1 $2" in
  "build "*) while [ $# -gt 0 ]; do case "$1" in --iidfile) echo sha256:0123 > "$2"; shift 2 ;; *) shift ;; esac; done ;;
  "image save") while [ $# -gt 0 ]; do case "$1" in -o) head -c 4096 /dev/zero > "$2"; shift 2 ;; *) shift ;; esac; done ;;
  "image inspect") echo sha256:0123 ;;
  "inspect "*) echo "$STUB_LABEL" ;;
  "run "*) echo "$STUB_RUN" ;;
  *) : ;;
esac`)
	stub(t, bin, "trivy", "case \" $* \" in *' --exit-code 0 '*) exit 0 ;; esac; exit 1\n")
	stub(t, bin, "python3", "exit 0\n")
	// The harness checks before the scan read labels and command output; the stub cannot
	// satisfy every one, so the scan is reached only if the script gets there. Run the scan
	// part directly instead: the same functions, the same trap.
	script := `. hack/ci/lib.sh
iids=$(mktemp -d "${TMPDIR:-/tmp}/agent-sandbox-ci-iid.XXXXXX")
ci_images_cleanup() { rm -rf "$iids"; }
trap ci_images_cleanup EXIT
echo sha256:0123 > "$iids/sandboxd"
id=$(cat "$iids/sandboxd")
docker image save -o "$iids/sandboxd.tar" "$id" || ci_die "images: cannot export"
ci_trivy_scan image "" --input "$iids/sandboxd.tar" || ci_die "images: fixable HIGH or CRITICAL vulnerabilities"
ci_ok images`
	cmd := exec.Command("bash", "-c", script)
	cmd.Dir = repoRoot(t)
	cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"), "TMPDIR="+tmp, "TRIVY_BIN="+filepath.Join(bin, "trivy"), "CI_BIN="+t.TempDir())
	out, err := cmd.CombinedOutput()
	if err == nil || strings.Contains(string(out), "ci: images: ok") {
		t.Fatalf("a failing verdict must fail the check: %v\n%s", err, out)
	}
	if left, _ := filepath.Glob(filepath.Join(tmp, "agent-sandbox-ci-iid.*")); len(left) != 0 {
		t.Fatalf("the exported archives must be removed when the verdict fails: %v", left)
	}
	// And the script itself registers that trap right where the directory is created, before
	// any build, and keeps it in the later Docker cleanup.
	src, _ := os.ReadFile(filepath.Join(repoRoot(t), "hack/ci/images.sh"))
	if !strings.Contains(string(src), "trap ci_images_cleanup EXIT") || strings.Count(string(src), `rm -rf "$iids"`) < 2 {
		t.Fatal("images.sh must remove the archive directory from its exit trap, in both cleanup definitions")
	}
}

// The acceptance scripts parse, name the same phases the runbook documents, and take their
// tool versions from versions.env like every other check.
func TestAcceptanceScriptsParseAndNameEveryPhase(t *testing.T) {
	root := repoRoot(t)
	for _, s := range []string{"hack/acceptance/lib.sh", "hack/acceptance/run.sh", "hack/acceptance/kind.sh", "hack/ci/acceptance.sh"} {
		if out, err := exec.Command("bash", "-n", filepath.Join(root, s)).CombinedOutput(); err != nil {
			t.Errorf("%s does not parse: %v\n%s", s, err, out)
		}
	}
	out, err := exec.Command(filepath.Join(root, "hack/acceptance/run.sh"), "--list").CombinedOutput()
	if err != nil {
		t.Fatalf("run.sh --list: %v\n%s", err, out)
	}
	phases := strings.Fields(string(out))
	want := []string{"preflight", "install", "config", "agent", "replicas", "recovery", "upgrade", "backup", "teardown"}
	if strings.Join(phases, " ") != strings.Join(want, " ") {
		t.Errorf("phases: %v, want %v", phases, want)
	}
	doc, err := os.ReadFile(filepath.Join(root, "docs/acceptance.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range want {
		if !strings.Contains(string(doc), "`"+p+"`") {
			t.Errorf("docs/acceptance.md does not document the %s phase", p)
		}
	}
	env, err := os.ReadFile(filepath.Join(root, "hack/ci/versions.env"))
	if err != nil {
		t.Fatal(err)
	}
	for _, pin := range []string{"KIND_VERSION=", "KIND_NODE_IMAGE=", "KUBECTL_VERSION=", "MULTUS_VERSION=", "WHEREABOUTS_VERSION=", "CNI_PLUGINS_VERSION="} {
		if !strings.Contains(string(env), pin) {
			t.Errorf("versions.env lacks %s", pin)
		}
	}
	kind, _ := os.ReadFile(filepath.Join(root, "hack/acceptance/kind.sh"))
	for _, bad := range []string{"kindest/node:v", "multus-cni/v", "whereabouts/v", "plugins/releases/download/v"} {
		if strings.Contains(string(kind), bad) {
			t.Errorf("kind.sh carries a version of its own (%q): versions live in versions.env", bad)
		}
	}
}

// The dependency scan is Trivy's verdict and nothing else: a scanner that finds a fixable
// finding fails the group, named, and a clean scanner passes it. The report pass shows every
// finding and the verdict pass carries the pinned policy (severity, fixed only, the ignore
// file, the repository's configuration file); the runner's TRIVY_* variables, which could skip
// the scan or widen what is ignored, never reach the scanner.
func TestScanPropagatesTrivyVerdict(t *testing.T) {
	mod := module(t)
	bin := t.TempDir()
	// The stub records each invocation's arguments and the TRIVY_* variables it sees. The
	// report pass (--exit-code 0) always succeeds, as Trivy's does; the verdict pass exits
	// with the code in the file next to the stub (the environment does not reach it), so a
	// failing verdict is what the test exercises, not a scanner that fails before it.
	stub(t, bin, "trivy", "d=$(dirname \"$0\"); echo \"$@\" >> \"$d/args\"; env | grep '^TRIVY_' >> \"$d/env\" || true\n"+
		"case \" $* \" in *' --exit-code 0 '*) exit 0 ;; esac; exit \"$(cat \"$d/exit\")\"\n")
	setExit := func(code string) {
		if err := os.WriteFile(filepath.Join(bin, "exit"), []byte(code), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	runsSeen := func() []string {
		args, _ := os.ReadFile(filepath.Join(bin, "args"))
		os.Remove(filepath.Join(bin, "args"))
		return strings.Split(strings.TrimSpace(string(args)), "\n")
	}
	setExit("0")
	// A runner's environment that would skip the scan, widen what is ignored, or, through
	// the verdict's skip list, empty the verdict: none of it may count.
	env := map[string]string{"CI_ROOT": mod, "TRIVY_BIN": filepath.Join(bin, "trivy"), "TRIVY_IGNORE_STATUS": "fixed", "TRIVY_DOWNLOAD_DB_ONLY": "true", "CI_TRIVY_GATE_SKIP": "."}
	out, err := runScript(t, "hack/ci/scan.sh", env, bin)
	if err != nil || !strings.HasSuffix(strings.TrimSpace(out), "ci: scan: ok") {
		t.Fatalf("a clean scan must pass: %v\n%s", err, out)
	}
	runs := runsSeen()
	if len(runs) != 2 {
		t.Fatalf("the scan is a report and a verdict, two runs; ran %d:\n%s", len(runs), strings.Join(runs, "\n"))
	}
	if strings.Contains(" "+runs[1]+" ", " --skip-dirs . ") {
		t.Fatalf("an inherited CI_TRIVY_GATE_SKIP must not reach the verdict; ran: %s", runs[1])
	}
	for _, want := range []string{"fs ", "--severity HIGH,CRITICAL", "--exit-code 0", "--ignorefile " + filepath.Join(mod, ".trivyignore.yaml"), "--config "} {
		if !strings.Contains(runs[0], want) {
			t.Fatalf("the report must run Trivy with %q; ran: %s", want, runs[0])
		}
	}
	if strings.Contains(runs[0], "--ignore-unfixed") {
		t.Fatalf("the report must show unfixed findings too; ran: %s", runs[0])
	}
	for _, want := range []string{"fs ", "--severity HIGH,CRITICAL", "--ignore-unfixed", "--exit-code 1", "--ignorefile " + filepath.Join(mod, ".trivyignore.yaml"), "--config "} {
		if !strings.Contains(runs[1], want) {
			t.Fatalf("the verdict must run Trivy with %q; ran: %s", want, runs[1])
		}
	}
	seen, _ := os.ReadFile(filepath.Join(bin, "env"))
	for _, leaked := range []string{"TRIVY_IGNORE_STATUS", "TRIVY_DOWNLOAD_DB_ONLY"} {
		if strings.Contains(string(seen), leaked) {
			t.Fatalf("the runner's %s must not reach the scanner; it saw:\n%s", leaked, seen)
		}
	}
	if !strings.Contains(string(seen), "TRIVY_CACHE_DIR=") {
		t.Fatalf("the scanner must get the cache directory from the script; it saw:\n%s", seen)
	}
	// A failing verdict fails the group, named, after the report ran.
	setExit("1")
	out, err = runScript(t, "hack/ci/scan.sh", env, bin)
	if err == nil || strings.Contains(out, "ci: scan: ok") || !strings.Contains(out, "vulnerabilities") {
		t.Fatalf("a scanner that finds a fixable finding must fail the group, named: %v\n%s", err, out)
	}
	if runs = runsSeen(); len(runs) != 2 || !strings.Contains(runs[1], "--exit-code 1") {
		t.Fatalf("the failing verdict must come from the second run; ran:\n%s", strings.Join(runs, "\n"))
	}
	// A scanner that cannot scan at all (the report pass itself fails) is a failure too.
	stub(t, bin, "trivy", "echo 'FATAL no database' >&2; exit 2\n")
	out, err = runScript(t, "hack/ci/scan.sh", env, bin)
	if err == nil || strings.Contains(out, "ci: scan: ok") {
		t.Fatalf("a scanner that fails to scan must fail the group: %v\n%s", err, out)
	}
}

// A Trivy download whose archive does not extract (a truncated download that still matched
// what the checksum file said, a full disk) fails the download, and leaves no file a later
// run would take for the scanner.
func TestTrivyDownloadRefusesAnArchiveThatDoesNotExtract(t *testing.T) {
	bin := t.TempDir()
	// A curl that serves garbage for the archive and a checksum file that vouches for it.
	stub(t, bin, "curl", `out=""; url=""
while [ $# -gt 0 ]; do case "$1" in -o) out=$2; shift 2 ;; http*) url=$1; shift ;; *) shift ;; esac; done
case "$url" in
  *checksums.txt) name=$(basename "$(dirname "$out")"); printf 'not an archive' > "$out.tmp"
    sum=$( (sha256sum "$out.tmp" 2>/dev/null || shasum -a 256 "$out.tmp") | awk '{print $1}'); rm -f "$out.tmp"
    for n in $(ls "$(dirname "$out")" | grep '\.tar\.gz$'); do echo "$sum  $n"; done > "$out" ;;
  *.tar.gz) printf 'not an archive' > "$out" ;;
  *) exit 22 ;;
esac
`)
	ciBin := t.TempDir()
	cmd := exec.Command("bash", "-c", ". hack/ci/lib.sh && ci_trivy")
	cmd.Dir = repoRoot(t)
	cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"), "CI_BIN="+ciBin, "TRIVY_BIN=")
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "cannot extract") {
		t.Fatalf("an archive that does not extract must fail the download, named: %v\n%s", err, out)
	}
	matches, _ := filepath.Glob(filepath.Join(ciBin, "trivy-*", "trivy"))
	if len(matches) != 0 {
		t.Fatalf("a failed download must leave no scanner behind: %v", matches)
	}
	if leftovers, _ := filepath.Glob(filepath.Join(ciBin, "trivy-download.*")); len(leftovers) != 0 {
		t.Fatalf("a failed download must clean its scratch directory: %v", leftovers)
	}
}

// A cold download is tried the way it will be run: a runner's Trivy settings (an unreadable
// TRIVY_CONFIG, a trivy.yaml in the working directory) do not reject a good archive.
func TestTrivyDownloadIgnoresAmbientTrivySettings(t *testing.T) {
	bin := t.TempDir()
	// A curl that serves an archive holding a "trivy" that refuses to run when it sees any
	// TRIVY_* setting but the cache directory, or a configuration file other than ours.
	stub(t, bin, "curl", `out=""; url=""
while [ $# -gt 0 ]; do case "$1" in -o) out=$2; shift 2 ;; http*) url=$1; shift ;; *) shift ;; esac; done
case "$url" in
  *checksums.txt)
    sum=$( (sha256sum "$(dirname "$out")"/*.tar.gz 2>/dev/null || shasum -a 256 "$(dirname "$out")"/*.tar.gz) | awk '{print $1}')
    for n in $(ls "$(dirname "$out")" | grep '\.tar\.gz$'); do echo "$sum  $n"; done > "$out" ;;
  *.tar.gz)
    d=$(mktemp -d); printf '#!/usr/bin/env bash\nif env | grep "^TRIVY_" | grep -qv "^TRIVY_CACHE_DIR="; then exit 3; fi\ncase " $* " in *"hack/ci/trivy.yaml"*) ;; *) exit 4 ;; esac\necho "Version: stub"\n' > "$d/trivy"
    chmod +x "$d/trivy"; tar -C "$d" -czf "$out" trivy; rm -rf "$d" ;;
  *) exit 22 ;;
esac
`)
	ciBin := t.TempDir()
	cmd := exec.Command("bash", "-c", ". hack/ci/lib.sh && ci_trivy")
	cmd.Dir = repoRoot(t)
	cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"), "CI_BIN="+ciBin, "TRIVY_BIN=",
		"TRIVY_CONFIG=/nonexistent/trivy.yaml", "TRIVY_DOWNLOAD_DB_ONLY=true")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("a good archive must be kept whatever Trivy settings the runner carries: %v\n%s", err, out)
	}
	if matches, _ := filepath.Glob(filepath.Join(ciBin, "trivy-*", "trivy")); len(matches) != 1 {
		t.Fatalf("the download must publish one scanner: %v", matches)
	}
}
