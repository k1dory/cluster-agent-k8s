package ci

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Only fixture values and inert tools are used: these tests never contact a cluster.
const reviewAcceptanceCredential = "1111111111111111111111111111111111111111111111111111111111111111"
const reviewAcceptancePreview = "22222222222222222222222222222222"

func reviewAcceptanceWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
}

func reviewAcceptanceFixture(t *testing.T) (string, map[string]string) {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate acceptance scripts")
	}
	source := filepath.Join(filepath.Dir(file), "../..")
	root := t.TempDir()
	for _, name := range []string{"hack/acceptance/run.sh", "hack/acceptance/kind.sh", "hack/acceptance/lib.sh", "hack/ci/lib.sh", "hack/ci/versions.env"} {
		body, err := os.ReadFile(filepath.Join(source, name))
		if err != nil {
			t.Fatal(err)
		}
		reviewAcceptanceWrite(t, filepath.Join(root, name), string(body))
	}
	bin := filepath.Join(root, "bin")
	reviewAcceptanceWrite(t, filepath.Join(bin, "kubectl"), `#!/usr/bin/env bash
set -eu
case "$*" in
  *"get secret "*)
    echo read >> "$REVIEW_TRACE"
    if [ "$REVIEW_READ_ERROR" = 1 ]; then echo 'fixture: temporary read failure' >&2; exit 1; fi
    case "$*" in
      *CREDENTIALS_KEY*) printf '%s' "$REVIEW_EXISTING_CREDENTIAL" | base64 ;;
      *PREVIEW_TICKET_KEY*) printf '%s' "$REVIEW_EXISTING_PREVIEW" | base64 ;;
      *)
        creds=$(printf '%s' "$REVIEW_EXISTING_CREDENTIAL" | base64 | tr -d '\n')
        preview=$(printf '%s' "$REVIEW_EXISTING_PREVIEW" | base64 | tr -d '\n')
        printf '{"data":{"CREDENTIALS_KEY":"%s","PREVIEW_TICKET_KEY":"%s"}}\n' "$creds" "$preview" ;;
    esac ;;
  *"create secret generic "*)
    echo create >> "$REVIEW_TRACE"
    printf '%s\n' "$@" > "$REVIEW_WRITTEN"
    echo '{}' ;;
  "apply -f -") cat >/dev/null; echo apply >> "$REVIEW_TRACE" ;;
  *) exit 0 ;;
esac
`)
	reviewAcceptanceWrite(t, filepath.Join(bin, "helm"), "#!/usr/bin/env bash\necho 'fixture: stop before rollout' >&2\nexit 61\n")
	reviewAcceptanceWrite(t, filepath.Join(bin, "kind"), "#!/usr/bin/env bash\nexit 0\n")
	for _, name := range []string{"curl", "docker", "git", "go", "sandboxctl"} {
		reviewAcceptanceWrite(t, filepath.Join(bin, name), "#!/usr/bin/env bash\necho 'fixture: unexpected external tool' >&2\nexit 62\n")
	}
	out := filepath.Join(root, "out")
	reviewAcceptanceWrite(t, filepath.Join(out, "state.env"), "ADMIN=fixture-admin\n")
	env := map[string]string{
		"PATH":                       bin + string(os.PathListSeparator) + os.Getenv("PATH"),
		"HOME":                       root,
		"TMPDIR":                     root,
		"KUBECONFIG":                 filepath.Join(root, "no-cluster"),
		"CI_BIN":                     bin,
		"KUBECTL":                    filepath.Join(bin, "kubectl"),
		"HELM":                       filepath.Join(bin, "helm"),
		"KIND":                       filepath.Join(bin, "kind"),
		"ACCEPT_SANDBOXCTL":          filepath.Join(bin, "sandboxctl"),
		"ACCEPT_OUT":                 out,
		"ACCEPT_DATABASE_URL":        "fixture-database",
		"ACCEPT_CREDENTIALS_KEY":     "",
		"ACCEPT_PREVIEW_TICKET_KEY":  "",
		"REVIEW_READ_ERROR":          "0",
		"REVIEW_EXISTING_CREDENTIAL": reviewAcceptanceCredential,
		"REVIEW_EXISTING_PREVIEW":    reviewAcceptancePreview,
		"REVIEW_TRACE":               filepath.Join(root, "trace"),
		"REVIEW_WRITTEN":             filepath.Join(root, "written"),
		"REVIEW_CAPTURE":             filepath.Join(root, "captured"),
	}
	return root, env
}

func reviewAcceptanceRun(t *testing.T, root string, env map[string]string, script string, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", append([]string{filepath.Join(root, script)}, args...)...)
	cmd.Dir = root
	cmd.WaitDelay = time.Second
	for name, value := range env {
		cmd.Env = append(cmd.Env, name+"="+value)
	}
	body, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("acceptance fixture timed out: %s", body)
	}
	return string(body), err
}

func TestReviewAcceptanceInstallKeepsKeysAndStopsOnReadFailure(t *testing.T) {
	for _, readError := range []bool{false, true} {
		name := "existing_keys"
		if readError {
			name = "read_error"
		}
		t.Run(name, func(t *testing.T) {
			root, env := reviewAcceptanceFixture(t)
			if readError {
				env["REVIEW_READ_ERROR"] = "1"
			}
			out, err := reviewAcceptanceRun(t, root, env, "hack/acceptance/run.sh", "install")
			if err == nil {
				t.Fatalf("fixture must stop before a rollout: %s", out)
			}
			trace, err := os.ReadFile(env["REVIEW_TRACE"])
			if err != nil || !strings.Contains(string(trace), "read\n") {
				t.Fatalf("install never read the existing Secret: %v\n%s", err, out)
			}
			if readError {
				if strings.Contains(string(trace), "create\n") || strings.Contains(string(trace), "apply\n") {
					t.Fatalf("install must abort before writing the Secret when its keys cannot be read; actions: %s", trace)
				}
				return
			}
			written, err := os.ReadFile(env["REVIEW_WRITTEN"])
			if err != nil || !strings.Contains(out, "fixture: stop before rollout") {
				t.Fatalf("positive control did not reach Secret creation and Helm: %v\n%s", err, out)
			}
			for _, want := range []string{"--from-literal=CREDENTIALS_KEY=" + reviewAcceptanceCredential, "--from-literal=PREVIEW_TICKET_KEY=" + reviewAcceptancePreview} {
				if !strings.Contains(string(written), want+"\n") {
					t.Error("install did not preserve an existing fixture key")
				}
			}
		})
	}
}

func TestReviewAcceptanceKindRunDoesNotRequestImplicitKeyRotation(t *testing.T) {
	for _, explicit := range []string{"", reviewAcceptanceCredential} {
		name := "existing_cluster"
		if explicit != "" {
			name = "explicit_key"
		}
		t.Run(name, func(t *testing.T) {
			root, env := reviewAcceptanceFixture(t)
			env["ACCEPT_CREDENTIALS_KEY"] = explicit
			// A retained kind cluster has the key file established by its first install.
			keyFile := filepath.Join(env["ACCEPT_OUT"], "credentials-key")
			if err := os.WriteFile(keyFile, []byte(reviewAcceptanceCredential), 0o600); err != nil {
				t.Fatal(err)
			}
			reviewAcceptanceWrite(t, filepath.Join(root, "hack/acceptance/run.sh"), "#!/usr/bin/env bash\nprintf '%s' \"${ACCEPT_CREDENTIALS_KEY:-}\" > \"$REVIEW_CAPTURE\"\n")
			out, err := reviewAcceptanceRun(t, root, env, "hack/acceptance/kind.sh", "run", "install")
			if err != nil {
				t.Fatalf("kind run: %v\n%s", err, out)
			}
			captured, err := os.ReadFile(env["REVIEW_CAPTURE"])
			if err != nil {
				t.Fatal(err)
			}
			// An unset input can delegate lookup to run.sh, or kind can reuse the Secret.
			if explicit == "" && (len(captured) == 0 || string(captured) == reviewAcceptanceCredential) {
				return
			}
			if string(captured) != explicit {
				t.Fatal("kind run supplied a new encryption key although the caller did not request rotation")
			}
		})
	}
}

func TestReviewAcceptanceKindFirstRunKeepsKeyForNextRun(t *testing.T) {
	root, env := reviewAcceptanceFixture(t)
	reviewAcceptanceWrite(t, filepath.Join(root, "hack/acceptance/run.sh"), "#!/usr/bin/env bash\nprintf '%s' \"${ACCEPT_CREDENTIALS_KEY:-}\" > \"$REVIEW_CAPTURE\"\n")
	var previous string
	for i := range 2 {
		out, err := reviewAcceptanceRun(t, root, env, "hack/acceptance/kind.sh", "run", "install")
		if err != nil {
			t.Fatalf("kind run %d: %v\n%s", i+1, err, out)
		}
		captured, err := os.ReadFile(env["REVIEW_CAPTURE"])
		if err != nil || len(captured) != 64 {
			t.Fatalf("kind did not pass a 32-byte hex key: %v", err)
		}
		if i > 0 && string(captured) != previous {
			t.Fatal("a second kind run replaced the first run's encryption key")
		}
		previous = string(captured)
	}
	info, err := os.Stat(filepath.Join(env["ACCEPT_OUT"], "credentials-key"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("persisted kind key must have mode 0600: %v", err)
	}
}
