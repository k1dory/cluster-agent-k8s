package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

type reviewAdapterJob struct {
	Defaults struct {
		Run struct {
			Shell string `yaml:"shell"`
		} `yaml:"run"`
	} `yaml:"defaults"`
	Steps  []struct{ Run, Shell string } `yaml:"steps"`
	Script []string                      `yaml:"script"`
	Rules  []struct{ If, When string }   `yaml:"rules"`
}

func reviewAdapterJobFromFile(t *testing.T, provider, job string) (reviewAdapterJob, string) {
	t.Helper()
	file := "../../deploy/git/github/sandbox-config.yml"
	if provider == "gitlab" {
		file = "../../deploy/git/gitlab/.gitlab-ci.yml"
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if provider == "github" {
		var wf struct {
			Defaults struct {
				Run struct {
					Shell string `yaml:"shell"`
				} `yaml:"run"`
			} `yaml:"defaults"`
			Jobs map[string]reviewAdapterJob `yaml:"jobs"`
		}
		if err := yaml.Unmarshal(raw, &wf); err != nil {
			t.Fatal(err)
		}
		j, ok := wf.Jobs[job]
		if !ok {
			t.Fatalf("missing %s job", job)
		}
		shell := wf.Defaults.Run.Shell
		if j.Defaults.Run.Shell != "" {
			shell = j.Defaults.Run.Shell
		}
		return j, shell
	}
	var nodes map[string]yaml.Node
	if err := yaml.Unmarshal(raw, &nodes); err != nil {
		t.Fatal(err)
	}
	n, ok := nodes[job]
	if !ok {
		t.Fatalf("missing %s job", job)
	}
	var j reviewAdapterJob
	if err := n.Decode(&j); err != nil {
		t.Fatal(err)
	}
	return j, "sh"
}

// Run the checked-in scripts with local stand-ins for external programs. Nothing calls
// Docker, GitHub or GitLab; the fixture controls only the program's report and exit status.
func reviewAdapterScript(t *testing.T, script, shell string, code int) (int, string, string) {
	t.Helper()
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	if err := os.MkdirAll(bin, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "bundles"), 0755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"first.yaml", "second.yaml"} {
		if err := os.WriteFile(filepath.Join(root, "bundles", name), []byte("fixture\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	programs := map[string]string{
		"docker": "#!/bin/sh\n" +
			// A first bundle succeeds: the comment is nonempty even when the next container
			// never starts. Docker infrastructure failures themselves produce no plan.
			"for arg in \"$@\"; do if [ \"$arg\" = bundles/first.yaml ]; then printf '%s\\n' '<!-- agent-sandbox -->' 'fixture report'; exit 0; fi; done\n" +
			"if [ \"$SANDBOX_REVIEW_RESULT\" -lt 125 ]; then printf '%s\\n' '<!-- agent-sandbox -->' 'fixture report'; fi\n" +
			"exit \"$SANDBOX_REVIEW_RESULT\"\n",
		"sandboxctl": "#!/bin/sh\nprintf '%s\\n' '<!-- agent-sandbox -->' 'fixture report'\nexit \"$SANDBOX_REVIEW_RESULT\"\n",
		"curl":       "#!/bin/sh\nprintf '%s\\n' called >> \"$SANDBOX_REVIEW_NOTES\"\nprintf '[]'\n",
		"jq":         "#!/bin/sh\ncase \"$1\" in -r) exit 0;; -Rs) printf '{\"body\":\"fixture report\"}';; esac\n",
	}
	for name, content := range programs {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(content), 0755); err != nil {
			t.Fatal(err)
		}
	}
	// The GitLab image uses an absolute binary path. Substitute that executable only;
	// the control flow, reports, status handling and note script remain verbatim.
	script = strings.ReplaceAll(script, "/sandboxctl ", "sandboxctl ")
	file := filepath.Join(root, "job.sh")
	if err := os.WriteFile(file, []byte(script), 0600); err != nil {
		t.Fatal(err)
	}
	program, args := "/bin/bash", []string{"-e"}
	switch shell {
	case "": // GitHub's unspecified Linux shell: bash -e, without pipefail.
	case "bash":
		args = []string{"--noprofile", "--norc", "-eo", "pipefail"}
	case "sh":
		program = "/bin/sh"
	default:
		t.Fatalf("unsupported shell in fixture: %s", shell)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, program, append(args, file)...)
	cmd.Dir = root
	notes := filepath.Join(root, "notes.log")
	cmd.Env = []string{"PATH=" + bin + ":/usr/bin:/bin", "SANDBOX_REVIEW_RESULT=" + fmt.Sprint(code), "SANDBOX_REVIEW_NOTES=" + notes,
		"SANDBOXD_URL=https://control.example.invalid", "SANDBOXD_TOKEN=fixture", "SANDBOXCTL_IMAGE=fixture", "SANDBOX_TENANT=acme",
		"GITHUB_STEP_SUMMARY=" + filepath.Join(root, "summary.md"), "GITLAB_TOKEN=fixture", "CI_API_V4_URL=https://git.example.invalid/api/v4",
		"CI_PROJECT_ID=1", "CI_MERGE_REQUEST_IID=1"}
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatal("script timed out")
	}
	status := 0
	if err != nil {
		var exited *exec.ExitError
		if !errors.As(err, &exited) {
			t.Fatal(err)
		}
		status = exited.ExitCode()
	}
	noteLog, _ := os.ReadFile(notes)
	return status, string(out), string(noteLog)
}

func TestReviewGitHubAdapterPreservesFailure(t *testing.T) {
	for _, tc := range []struct {
		job  string
		code int
	}{
		{"plan", 0}, {"plan", 1}, {"plan", 2}, {"plan", 125}, {"plan", 126}, {"plan", 127},
		{"drift", 0}, {"drift", 1}, {"drift", 3},
	} {
		t.Run(fmt.Sprintf("%s_exit_%d", tc.job, tc.code), func(t *testing.T) {
			job, shell := reviewAdapterJobFromFile(t, "github", tc.job)
			var script string
			for _, step := range job.Steps {
				if step.Run != "" {
					script = step.Run
					if step.Shell != "" {
						shell = step.Shell
					}
					break
				}
			}
			if script == "" {
				t.Fatal("missing run step")
			}
			status, _, _ := reviewAdapterScript(t, script, shell, tc.code)
			if (tc.code == 0) != (status == 0) {
				t.Errorf("%s program exit %d must remain a job failure/success; job returned %d", tc.job, tc.code, status)
			}
		})
	}
}

func TestReviewGitLabInvalidPlanStillPublishesReport(t *testing.T) {
	job, shell := reviewAdapterJobFromFile(t, "gitlab", "plan")
	status, _, notes := reviewAdapterScript(t, strings.Join(job.Script, "\n"), shell, 2)
	if status == 0 {
		t.Error("invalid plan must fail the job")
	}
	if notes == "" {
		t.Error("invalid plan must update the MR report before the job exits")
	}
}

func TestReviewGitLabScheduleDoesNotApply(t *testing.T) {
	job, _ := reviewAdapterJobFromFile(t, "gitlab", "apply")
	// On scheduled pipelines rules:changes is true without compare_to (GitLab contract).
	// These template conditions use the same equality/boolean syntax as bash [[ ... ]].
	for _, rule := range job.Rules {
		matches := rule.If == ""
		if rule.If != "" {
			cmd := exec.Command("/bin/bash", "-c", "[[ "+rule.If+" ]]")
			cmd.Env = []string{"CI_PIPELINE_SOURCE=schedule", "CI_COMMIT_BRANCH=main", "CI_DEFAULT_BRANCH=main"}
			err := cmd.Run()
			if err != nil {
				var exited *exec.ExitError
				if !errors.As(err, &exited) || exited.ExitCode() != 1 {
					t.Fatalf("cannot evaluate template condition: %v", err)
				}
			}
			matches = err == nil
		}
		if matches {
			if rule.When != "never" && rule.When != "manual" {
				t.Error("scheduled drift must not automatically enqueue apply on the default branch")
			}
			return
		}
	}
}
