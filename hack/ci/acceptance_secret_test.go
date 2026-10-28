package ci_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The install phase rewrites Secret agent-sandbox-secrets. These tests run the functions it uses
// (hack/acceptance/lib.sh) against a stand-in kubectl: an unreadable Secret must stop the install
// instead of being rewritten without CREDENTIALS_KEY, an explicit key must not replace the one the
// stored credentials are encrypted under, and a kept kind cluster keeps one key across installs.

// accSecretShell runs script after sourcing lib.sh, with kubectl answering as the mode says.
func accSecretShell(t *testing.T, mode, script string, env ...string) (string, error) {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	kubectl := filepath.Join(dir, "kubectl")
	stub := `#!/usr/bin/env bash
case "$FAKE_SECRET" in
  missing) echo 'Error from server (NotFound): secrets "agent-sandbox-secrets" not found' >&2; exit 1 ;;
  forbidden) echo 'Error from server (Forbidden): secrets "agent-sandbox-secrets" is forbidden' >&2; exit 1 ;;
  unreachable) echo 'The connection to the server 10.0.0.1:6443 was refused' >&2; exit 1 ;;
  keyed) echo '{"data":{"CREDENTIALS_KEY":"b2xkLWtleQ==","PREVIEW_TICKET_KEY":"b2xkLXByZXZpZXc="}}' ;;
  bare) echo '{"data":{"SANDBOXD_API_TOKEN":"dA=="}}' ;;
esac
`
	if err := os.WriteFile(kubectl, []byte(stub), 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "-c", `. hack/acceptance/lib.sh; `+script, "acc", kubectl)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), append([]string{"FAKE_SECRET=" + mode, "ACCEPT_OUT=" + filepath.Join(dir, "out"),
		"ACCEPT_CREDENTIALS_KEY=", "ACCEPT_PREVIEW_TICKET_KEY="}, env...)...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

const accDecide = `data=$(acc_secret_data "$1" ns) && acc_secret_keys "$data" && echo "creds=$ACC_CREDENTIALS_KEY preview=$ACC_PREVIEW_TICKET_KEY"`

func TestAcceptanceSecretUnreadableStopsTheInstall(t *testing.T) {
	for _, mode := range []string{"forbidden", "unreachable"} {
		out, err := accSecretShell(t, mode, accDecide)
		if err == nil || strings.Contains(out, "creds=") {
			t.Fatalf("%s: an unreadable Secret was taken for an empty one: %v\n%s", mode, err, out)
		}
		if !strings.Contains(out, "refusing to rewrite") {
			t.Fatalf("%s: the failure does not say why: %s", mode, out)
		}
	}
}

func TestAcceptanceSecretKeysComeFromTheSecretOrTheInput(t *testing.T) {
	cases := []struct {
		mode, input, want string
	}{
		{"missing", "", "creds= preview="},               // first install, no key asked: credentials API off
		{"missing", "new-key", "creds=new-key preview="}, // first install with a key
		{"keyed", "", "creds=old-key preview=old-preview"},
		{"keyed", "old-key", "creds=old-key preview=old-preview"},
		{"bare", "", "creds= preview="},
	}
	for _, c := range cases {
		out, err := accSecretShell(t, c.mode, accDecide, "ACCEPT_CREDENTIALS_KEY="+c.input)
		if err != nil || !strings.Contains(out, c.want) {
			t.Fatalf("%s with input %q: want %q: %v\n%s", c.mode, c.input, c.want, err, out)
		}
		if strings.HasSuffix(strings.TrimSpace(out), "preview=") {
			t.Fatalf("%s: no preview key generated: %s", c.mode, out)
		}
	}
}

func TestAcceptanceSecretRefusesToReplaceTheStoredKey(t *testing.T) {
	out, err := accSecretShell(t, "keyed", accDecide, "ACCEPT_CREDENTIALS_KEY=other-key")
	if err == nil || strings.Contains(out, "creds=") || !strings.Contains(out, "stored credentials unreadable") {
		t.Fatalf("an explicit key replaced the stored one: %v\n%s", err, out)
	}
}

func TestAcceptanceKindKeepsOneCredentialsKeyPerCluster(t *testing.T) {
	out, err := accSecretShell(t, "missing", `f="$ACCEPT_OUT/credentials-key"; a=$(acc_kept_credentials_key "$f"); b=$(acc_kept_credentials_key "$f"); echo "a=$a b=$b mode=$(stat -c %a "$f" 2>/dev/null || stat -f %Lp "$f")"`)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	var a, b, mode string
	for _, f := range strings.Fields(out) {
		switch {
		case strings.HasPrefix(f, "a="):
			a = f[2:]
		case strings.HasPrefix(f, "b="):
			b = f[2:]
		case strings.HasPrefix(f, "mode="):
			mode = f[5:]
		}
	}
	if len(a) != 64 || a != b || mode != "600" {
		t.Fatalf("a second install got another key or a readable file: a=%q b=%q mode=%q", a, b, mode)
	}
}
