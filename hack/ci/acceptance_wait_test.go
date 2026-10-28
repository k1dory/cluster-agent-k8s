package ci_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// accLib runs script after sourcing hack/acceptance/lib.sh, under the scripts' own pipefail.
func accLib(t *testing.T, script string) (string, error) {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "-c", `. hack/acceptance/lib.sh; set -o pipefail; `+script)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "ACCEPT_OUT="+t.TempDir())
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// A command that keeps writing after the line a check looks for (sandboxctl apply -markdown
// prints its table after "Apply ✅ done") must pass the check: with `| grep -q` the writer got
// SIGPIPE and, under pipefail, an apply that went through was reported failed (live cluster).
func TestAcceptanceContainsReadsTheWholeStream(t *testing.T) {
	writer := `{ echo "Apply ✅ done"; for i in $(seq 1 20000); do echo "| step $i | done |"; done; }`
	if out, err := accLib(t, writer+` | acc_contains "Apply ✅ done" && echo matched`); err != nil || !strings.Contains(out, "matched") {
		t.Fatalf("the text was there: %v\n%s", err, out)
	}
	if out, err := accLib(t, writer+` | acc_contains "Apply ⏸ did not finish" && echo matched`); err == nil || strings.Contains(out, "matched") {
		t.Fatalf("absent text matched: %s", out)
	}
}

// Waiting for a run ends on its terminal states only: an empty status (the request failed) or
// running/queued keeps waiting. The old condition (not running and not queued) took an empty
// answer for the end and failed the phase with "run … ended running".
func TestAcceptanceRunEndsOnlyWhenItIsOver(t *testing.T) {
	for status, over := range map[string]bool{"done": true, "failed": true, "cancelled": true, "": false, "running": false, "queued": false, "null": false} {
		_, err := accLib(t, `acc_run_ended "`+status+`"`)
		if (err == nil) != over {
			t.Fatalf("status %q: over=%v, want %v", status, err == nil, over)
		}
	}
}
