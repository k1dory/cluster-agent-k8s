package ci

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// checkout makes a clean Git checkout of its own for the publish script (CI_ROOT): the script
// refuses a dirty tree, and the developer's tree may well be one.
func checkout(t *testing.T) (dir, head string) {
	t.Helper()
	dir = t.TempDir()
	run := func(args ...string) string {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	run("init", "-q")
	if err := os.WriteFile(filepath.Join(dir, "cosign.pub"), []byte("public\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".gitignore"), []byte("/.ci/\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", ".")
	run("commit", "-q", "-m", "x")
	return dir, run("rev-parse", "HEAD")
}

// publishStubs puts a docker and a cosign on PATH that record their arguments: buildx build
// writes the metadata file a real build writes (a digest per image), imagetools inspect finds
// the tag only when existing is set, cosign verify finds no signature.
func publishStubs(t *testing.T, existing string) (bin, dockerLog, cosignLog string) {
	t.Helper()
	bin, logs := t.TempDir(), t.TempDir()
	dockerLog, cosignLog = filepath.Join(logs, "docker.log"), filepath.Join(logs, "cosign.log")
	stub(t, bin, "docker", `printf '%s\n' "$*" >> "`+dockerLog+`"
case "$1 ${2:-} ${3:-}" in
  "buildx imagetools inspect") [ -n "`+existing+`" ] && { echo '{"digest":"`+existing+`"}'; exit 0; }; echo "ERROR: $4: not found" >&2; exit 1 ;;
  "buildx build "*)
    meta= tag=
    while [ $# -gt 0 ]; do case "$1" in --metadata-file) meta=$2; shift ;; -t) tag=$2; shift ;; esac; shift; done
    name=${tag%:*}; name=${name##*/}
    sum=$(printf '%s' "$name" | (sha256sum 2>/dev/null || shasum -a 256) | cut -c1-64)
    printf '{"containerimage.digest":"sha256:%s"}' "$sum" > "$meta" ;;
esac
exit 0
`)
	stub(t, bin, "cosign", `printf '%s\n' "$*" >> "`+cosignLog+`"
[ "$1" = verify ] && exit 1
exit 0
`)
	return bin, dockerLog, cosignLog
}

// A publish pushes linux/amd64 images under the commit's immutable tag only, with the pinned
// harnesses as the agent's build arguments, signs every pushed digest and records image,
// digest, arch, commit and harness versions.
func TestPublishSignsEveryDigestUnderTheCommitTag(t *testing.T) {
	dir, head := checkout(t)
	bin, dockerLog, cosignLog := publishStubs(t, "")
	out, err := runScript(t, "hack/publish-images.sh", map[string]string{
		"CI_ROOT": dir, "IMAGE_REPO": "registry.example.com/Org/Repo", "COSIGN_PRIVATE_KEY": "k", "COSIGN_BIN": filepath.Join(bin, "cosign"),
	}, bin)
	if err != nil {
		t.Fatalf("publish: %v\n%s", err, out)
	}
	tag := "sha-" + head[:12]
	builds := 0
	calls, _ := os.ReadFile(dockerLog)
	for _, line := range strings.Split(string(calls), "\n") {
		if !strings.HasPrefix(line, "buildx build ") {
			continue
		}
		builds++
		if !strings.Contains(line, "--platform linux/amd64") || !strings.Contains(line, "--push") || !strings.Contains(line, ":"+tag+" ") {
			t.Errorf("a build not pushed for linux/amd64 under %s: %s", tag, line)
		}
		if strings.Contains(line, ":latest") {
			t.Errorf("a build tagged latest: %s", line)
		}
		if !strings.Contains(line, "org.opencontainers.image.revision="+head) {
			t.Errorf("a build without its revision label: %s", line)
		}
		if strings.Contains(line, "/agent:") && (!strings.Contains(line, "CLAUDE_CODE_VERSION=") || !strings.Contains(line, "CODEX_VERSION=")) {
			t.Errorf("the agent built without the pinned harnesses: %s", line)
		}
	}
	if builds != 3 {
		t.Errorf("%d builds, want 3 (sandboxd, sandboxctl, agent)", builds)
	}
	var m struct {
		Commit  string            `json:"commit"`
		Tag     string            `json:"tag"`
		Signed  bool              `json:"signed"`
		Harness map[string]string `json:"harness"`
		Images  []struct {
			Name, Image, Digest, Ref, Arch string
		} `json:"images"`
	}
	b, err := os.ReadFile(filepath.Join(dir, ".ci/publish/images.json"))
	if err != nil {
		t.Fatalf("no manifest: %v\n%s", err, out)
	}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m.Commit != head || m.Tag != tag || !m.Signed || m.Harness["claude-code"] == "" || m.Harness["codex"] == "" || len(m.Images) != 3 {
		t.Fatalf("manifest: %s", b)
	}
	signs, _ := os.ReadFile(cosignLog)
	for _, i := range m.Images {
		if !strings.HasPrefix(i.Image, "registry.example.com/org/repo/") || i.Arch != "linux/amd64" || !strings.HasPrefix(i.Digest, "sha256:") || i.Ref != i.Image+"@"+i.Digest {
			t.Errorf("image record: %+v", i)
		}
		if !strings.Contains(string(signs), "sign --key env://COSIGN_PRIVATE_KEY "+i.Ref+"\n") {
			t.Errorf("%s was not signed by digest:\n%s", i.Ref, signs)
		}
	}
}

// An existing tag is never rebuilt (it is immutable): its digest is recorded and signed.
func TestPublishDoesNotRebuildAnExistingTag(t *testing.T) {
	dir, _ := checkout(t)
	digest := "sha256:" + strings.Repeat("ab", 32)
	bin, dockerLog, cosignLog := publishStubs(t, digest)
	out, err := runScript(t, "hack/publish-images.sh", map[string]string{
		"CI_ROOT": dir, "IMAGE_REPO": "registry.example.com/org/repo", "COSIGN_PRIVATE_KEY": "k", "COSIGN_BIN": filepath.Join(bin, "cosign"),
	}, bin)
	if err != nil {
		t.Fatalf("publish: %v\n%s", err, out)
	}
	if calls, _ := os.ReadFile(dockerLog); strings.Contains(string(calls), "buildx build") {
		t.Errorf("an existing tag was rebuilt:\n%s", calls)
	}
	if signs, _ := os.ReadFile(cosignLog); strings.Count(string(signs), "@"+digest) < 3 {
		t.Errorf("the existing digests were not verified and signed:\n%s", signs)
	}
}

// What a publish must have is checked before anything is built or pushed, and a missing key
// is a failure unless unsigned is asked for by name.
func TestPublishRefusesBeforePushing(t *testing.T) {
	cases := map[string]struct {
		env   map[string]string
		dirty bool
		want  string
	}{
		"no repository": {env: map[string]string{"COSIGN_PRIVATE_KEY": "k"}, want: "IMAGE_REPO is required"},
		"no key":        {env: map[string]string{"IMAGE_REPO": "r.example.com/o/r"}, want: "COSIGN_PRIVATE_KEY is not set"},
		"dirty":         {env: map[string]string{"IMAGE_REPO": "r.example.com/o/r", "COSIGN_PRIVATE_KEY": "k"}, dirty: true, want: "the checkout has changes"},
		"another commit": {env: map[string]string{"IMAGE_REPO": "r.example.com/o/r", "COSIGN_PRIVATE_KEY": "k", "COMMIT": strings.Repeat("0", 40)},
			want: "is not the checkout's HEAD"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			dir, _ := checkout(t)
			if c.dirty {
				if err := os.WriteFile(filepath.Join(dir, "stray.go"), []byte("package x\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			bin, dockerLog, _ := publishStubs(t, "")
			env := map[string]string{"CI_ROOT": dir, "COSIGN_BIN": filepath.Join(bin, "cosign")}
			for k, v := range c.env {
				env[k] = v
			}
			out, err := runScript(t, "hack/publish-images.sh", env, bin)
			if err == nil || !strings.Contains(out, c.want) {
				t.Fatalf("want a failure naming %q: %v\n%s", c.want, err, out)
			}
			if calls, _ := os.ReadFile(dockerLog); strings.Contains(string(calls), "buildx build") {
				t.Errorf("built before refusing:\n%s", calls)
			}
		})
	}
	// Unsigned on purpose: published, recorded as unsigned, cosign never asked to sign.
	dir, _ := checkout(t)
	bin, _, cosignLog := publishStubs(t, "")
	out, err := runScript(t, "hack/publish-images.sh", map[string]string{
		"CI_ROOT": dir, "IMAGE_REPO": "r.example.com/o/r", "PUBLISH_UNSIGNED": "1", "COSIGN_BIN": filepath.Join(bin, "cosign"),
	}, bin)
	if err != nil || !strings.Contains(out, `"signed": false`) {
		t.Fatalf("PUBLISH_UNSIGNED=1 must publish and record unsigned: %v\n%s", err, out)
	}
	if signs, _ := os.ReadFile(cosignLog); strings.Contains(string(signs), "sign ") {
		t.Errorf("signed although unsigned was asked for:\n%s", signs)
	}
}

// verify-images refuses an unsigned record and a tag that no longer names the recorded digest.
func TestVerifyImagesChecksTheRecordedDigest(t *testing.T) {
	dir, _ := checkout(t)
	bin := t.TempDir()
	recorded := "sha256:" + strings.Repeat("ab", 32)
	write := func(signed bool) {
		m := map[string]any{"commit": "c", "signed": signed, "images": []map[string]string{
			{"name": "agent", "tag": "sha-c", "digest": recorded, "image": "r.example.com/o/r/agent"}}}
		b, _ := json.Marshal(m)
		if err := os.MkdirAll(filepath.Join(dir, ".ci/publish"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, ".ci/publish/images.json"), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cosignAnswering := func(digest string) {
		stub(t, bin, "cosign", `echo '[{"critical":{"image":{"docker-manifest-digest":"`+digest+`"}}}]'`+"\n")
	}
	env := map[string]string{"CI_ROOT": dir, "COSIGN_BIN": filepath.Join(bin, "cosign")}

	write(true)
	cosignAnswering(recorded)
	if out, err := runScript(t, "hack/verify-images.sh", env, bin); err != nil || !strings.Contains(out, "signed") {
		t.Fatalf("a signed tag on its recorded digest must verify: %v\n%s", err, out)
	}
	cosignAnswering("sha256:" + strings.Repeat("cd", 32))
	if out, err := runScript(t, "hack/verify-images.sh", env, bin); err == nil || !strings.Contains(out, "the manifest recorded") {
		t.Fatalf("a tag that moved must fail: %v\n%s", err, out)
	}
	write(false)
	cosignAnswering(recorded)
	if out, err := runScript(t, "hack/verify-images.sh", env, bin); err == nil || !strings.Contains(out, "unsigned") {
		t.Fatalf("an unsigned record must fail: %v\n%s", err, out)
	}
}
