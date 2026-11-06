package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The flag goes to the claude invocation, not to whatever the shell runs after it: a trailing
// newline (a YAML block scalar), a `&& …`, a pipe or a comment keep their place; an argument
// that merely contains "system-prompt" is not a system-prompt option; a quoted assignment in
// front of the program is an assignment, not the program.
func TestInstructionsRespectShellSyntax(t *testing.T) {
	const flag = ` --append-system-prompt "$SANDBOX_INSTRUCTIONS"`
	for _, tc := range []struct{ in, want string }{
		{"claude -p \"$SANDBOX_TASK\"\n", "claude -p \"$SANDBOX_TASK\"" + flag + "\n"},
		{`claude -p "$SANDBOX_TASK" && echo done`, `claude -p "$SANDBOX_TASK"` + flag + ` && echo done`},
		{`claude -p "$SANDBOX_TASK" | tee run.log`, `claude -p "$SANDBOX_TASK"` + flag + ` | tee run.log`},
		{`claude -p "$SANDBOX_TASK"; echo done`, `claude -p "$SANDBOX_TASK"` + flag + `; echo done`},
		{`claude -p "$SANDBOX_TASK" # the shipped command`, `claude -p "$SANDBOX_TASK"` + flag + ` # the shipped command`},
		{`claude -p "Review system-prompt handling"`, `claude -p "Review system-prompt handling"` + flag},
		{`claude -p "a && b"`, `claude -p "a && b"` + flag},
		{`claude -p 'it'"'"'s' --verbose`, `claude -p 'it'"'"'s' --verbose` + flag},
		{`VAR="two words" claude -p "$SANDBOX_TASK"`, `VAR="two words" claude -p "$SANDBOX_TASK"` + flag},
		{`A=1 B='x y' /usr/local/bin/claude -p x`, `A=1 B='x y' /usr/local/bin/claude -p x` + flag},
		{`claude -p x 2>&1`, `claude -p x 2>&1` + flag},
		{`claude -p x 2>&1 | tee run.log`, `claude -p x 2>&1` + flag + ` | tee run.log`},
		{`claude -p x &> run.log`, `claude -p x &> run.log` + flag},
		{`claude --model $(cat /etc/model | tr -d '\n') -p x`, `claude --model $(cat /etc/model | tr -d '\n') -p x` + flag},
		{"claude --model `cat m | tr -d x` -p x", "claude --model `cat m | tr -d x` -p x" + flag},
		{`claude -p "$(echo a; echo b)" && echo done`, `claude -p "$(echo a; echo b)"` + flag + ` && echo done`},
		{`claude -p x $(f "$(g)") ; echo`, `claude -p x $(f "$(g)")` + flag + ` ; echo`},
		{`claude -p "$(printf "Task: %s; context: %s" "$SANDBOX_TASK" context)"`, `claude -p "$(printf "Task: %s; context: %s" "$SANDBOX_TASK" context)"` + flag},
		{`claude -p "$SANDBOX_TASK" >| run.log`, `claude -p "$SANDBOX_TASK" >| run.log` + flag},
		{`claude -p "$SANDBOX_TASK" >| run.log; echo`, `claude -p "$SANDBOX_TASK" >| run.log` + flag + `; echo`},
		{`claude -p -- "$SANDBOX_TASK"`, `claude -p` + flag + ` -- "$SANDBOX_TASK"`},
		{`claude -- "$SANDBOX_TASK" --system-prompt x`, `claude` + flag + ` -- "$SANDBOX_TASK" --system-prompt x`},
		{`claude -p "a -- b" x`, `claude -p "a -- b" x` + flag},
		{`claude --model $( (cat /etc/model || echo sonnet) | tr -d '[:space:]') -p "$SANDBOX_TASK"`, `claude --model $( (cat /etc/model || echo sonnet) | tr -d '[:space:]') -p "$SANDBOX_TASK"` + flag},
		{`claude -p "--" "$SANDBOX_TASK"`, `claude -p` + flag + ` "--" "$SANDBOX_TASK"`},
		{`claude -p '--' "$SANDBOX_TASK" --system-prompt x`, `claude -p` + flag + ` '--' "$SANDBOX_TASK" --system-prompt x`},
	} {
		if got := withInstructions(tc.in); got != tc.want {
			t.Errorf("%q\n got %q\nwant %q", tc.in, got, tc.want)
		}
	}
	for _, cmd := range []string{
		`claude -p x --system-prompt=brief`,
		`claude -p x --append-system-prompt-file=/etc/agent.md`,
		`claude -p x --system-prompt-file /etc/agent.md && echo done`,
		`claude -p x "--system-prompt" "operator policy"`,
		`claude -p x '--append-system-prompt=operator policy'`,
		`claude -p x --system\-prompt brief`,
		`claude-agent-acp`,
		`VAR=x claude-agent-acp --verbose`,
		`VAR="two words" codex exec "$SANDBOX_TASK"`,
		`echo claude`,
		`# claude -p x`,
	} {
		if got := withInstructions(cmd); got != cmd {
			t.Errorf("%q must be left alone, got %q", cmd, got)
		}
	}
	// withMCPConfig shares the parser.
	if got := withMCPConfig("claude -p x\n"); got != "claude -p x --mcp-config \"$SANDBOX_MCP_CONFIG\"\n" {
		t.Errorf("mcp config on a block scalar: %q", got)
	}
	if got := withMCPConfig(`claude -p "with --mcp-config in the text"`); !strings.HasSuffix(got, `--mcp-config "$SANDBOX_MCP_CONFIG"`) {
		t.Errorf("an argument mentioning the option is not the option: %q", got)
	}
	if cmd := `claude -p x "--mcp-config" /etc/mcp.json`; withMCPConfig(cmd) != cmd {
		t.Errorf("a quoted option is the option: %q", withMCPConfig(cmd))
	}
	if got := withMCPConfig(`claude -p x 2>&1 | tee log`); got != `claude -p x 2>&1 --mcp-config "$SANDBOX_MCP_CONFIG" | tee log` {
		t.Errorf("redirection and pipe: %q", got)
	}
}

// The rewritten command lines run: the shell gets the flag as claude's argument, and the rest of
// the line still runs after it.
func TestInstructionsRewriteRunsInTheShell(t *testing.T) {
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	if err := os.Mkdir(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	stub := filepath.Join(bin, "claude")
	if err := os.WriteFile(stub, []byte("#!/bin/sh\nprintf '%s\\0' \"$@\" > \"$SANDBOX_REVIEW_ARGS\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	const instructions = "Triage new incidents.\nQuote \"$HOME\" literally."
	for _, cmd := range []string{
		"claude -p \"$SANDBOX_TASK\" --verbose\n",
		`claude -p "$SANDBOX_TASK" && echo done > "$SANDBOX_REVIEW_ARGS.done"`,
		`VAR="two words" claude -p "$SANDBOX_TASK" # note`,
		`claude -p "$SANDBOX_TASK" 2>&1`,
		`claude --model $(printf opus | tr a-z A-Z) -p "$SANDBOX_TASK" && echo done > "$SANDBOX_REVIEW_ARGS.done"`,
		`claude -p "$(printf "Task: %s; context: %s" "$SANDBOX_TASK" context)"`,
		`claude -p "$SANDBOX_TASK" >| "$SANDBOX_REVIEW_ARGS.log"`,
		`claude -p -- "$SANDBOX_TASK"`,
		`claude -p "--" "$SANDBOX_TASK"`,
		`claude -p '--' "$SANDBOX_TASK"`,
		`claude --model $( (printf opus || echo x) | tr a-z A-Z) -p "$SANDBOX_TASK"`,
	} {
		argsFile := filepath.Join(root, "args")
		_ = os.Remove(argsFile)
		_ = os.Remove(argsFile + ".done")
		sh := exec.Command("/bin/sh", "-c", withInstructions(cmd))
		sh.Env = append(os.Environ(), "PATH="+bin+":/usr/bin:/bin", "SANDBOX_REVIEW_ARGS="+argsFile, "SANDBOX_TASK=task", "SANDBOX_INSTRUCTIONS="+instructions)
		if out, err := sh.CombinedOutput(); err != nil {
			t.Fatalf("%q: %v\n%s", cmd, err, out)
		}
		raw, err := os.ReadFile(argsFile)
		if err != nil {
			t.Fatalf("%q: claude did not run: %v", cmd, err)
		}
		parts := strings.Split(strings.TrimSuffix(string(raw), "\x00"), "\x00")
		got, at := "", -1
		for i, a := range parts {
			if a == "--append-system-prompt" && i+1 < len(parts) {
				got, at = parts[i+1], i
			}
		}
		if got != instructions {
			t.Fatalf("%q: claude's argv %q lacks the instructions", cmd, parts)
		}
		if dd := slices.Index(parts, "--"); dd >= 0 && at > dd {
			t.Fatalf("%q: the flag came after -- (argv %q)", cmd, parts)
		}
		if strings.Contains(cmd, "printf \"Task") && !slices.Contains(parts, "Task: task; context: context") {
			t.Fatalf("%q: the prompt built by the substitution was changed (argv %q)", cmd, parts)
		}
		if strings.Contains(cmd, ">|") {
			if _, err := os.Stat(argsFile + ".log"); err != nil {
				t.Fatalf("%q: the >| redirection did not happen", cmd)
			}
		}
		if strings.Contains(cmd, "printf opus") && !slices.Contains(parts, "OPUS") {
			t.Fatalf("%q: the substitution was not left intact: %q", cmd, parts)
		}
		if strings.Contains(cmd, "&&") {
			if _, err := os.Stat(argsFile + ".done"); err != nil {
				t.Fatalf("%q: the command after && did not run", cmd)
			}
		}
	}
}
