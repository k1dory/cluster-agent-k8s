package gitsync

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

	"agent-sandbox/internal/gitsync/gittest"
)

// loggingGit wraps git in a script that appends each invocation's arguments to a log; blob,
// when set, replaces every `cat-file blob` output with that shell command's.
func loggingGit(t *testing.T, blob string) (bin, log string) {
	t.Helper()
	real, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git is required")
	}
	dir := t.TempDir()
	bin, log = filepath.Join(dir, "git"), filepath.Join(dir, "log")
	script := fmt.Sprintf("#!/bin/sh\necho \"$*\" >> %q\n", log)
	if blob != "" {
		script += fmt.Sprintf("if [ \"$1\" = cat-file ] && [ \"$2\" = blob ]; then %s; exit 0; fi\n", blob)
	}
	script += fmt.Sprintf("exec %q \"$@\"\n", real)
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, log
}

func readLog(t *testing.T, log string) string {
	b, _ := os.ReadFile(log)
	return string(b)
}

// A bundle file over MaxFile used to be read whole into memory by git cat-file and refused
// only afterwards; its size is now asked first and its content never read.
func TestOversizedBundleIsRefusedUnreadRound2(t *testing.T) {
	g := gittest.New(t, "", "")
	sha := g.Commit(t, map[string]string{
		"bundles/a.yaml":   "kind: EnvironmentProfile\nname: a\n",
		"bundles/big.yaml": strings.Repeat("x: 1234567890\n", MaxFile/14+100),
	}, "big")
	bin, log := loggingGit(t, "")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_, err := CLI{Git: bin}.Files(ctx, Remote{URL: g.URL, Ref: "main"}, sha, []string{"bundles/*.yaml"})
	if !errors.Is(err, ErrTooLarge) || !strings.Contains(err.Error(), "bundles/big.yaml") {
		t.Fatalf("an oversized bundle: %v", err)
	}
	if l := readLog(t, log); strings.Contains(l, "cat-file blob") {
		t.Fatalf("a blob was read although the set is refused:\n%s", l)
	}
}

// No bound on the set used to exist: MaxFiles small files or a set over MaxTotal were read and
// returned whole.
func TestBundleSetIsBoundedRound2(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	t.Run("count", func(t *testing.T) {
		g := gittest.New(t, "", "")
		files := map[string]string{}
		for i := 0; i <= MaxFiles; i++ {
			files[fmt.Sprintf("bundles/f%03d.yaml", i)] = "x: 1\n"
		}
		sha := g.Commit(t, files, "many")
		bin, log := loggingGit(t, "")
		if _, err := (CLI{Git: bin}).Files(ctx, Remote{URL: g.URL, Ref: "main"}, sha, []string{"bundles/*.yaml"}); !errors.Is(err, ErrTooLarge) {
			t.Fatalf("%d files: %v", MaxFiles+1, err)
		}
		if l := readLog(t, log); strings.Contains(l, "cat-file") {
			t.Fatal("files were read although there are too many")
		}
	})
	t.Run("total", func(t *testing.T) {
		g := gittest.New(t, "", "")
		files := map[string]string{}
		one := strings.Repeat("y: 1234567890\n", (MaxFile-100)/14)
		for i := 0; i*len(one) <= MaxTotal; i++ {
			files[fmt.Sprintf("bundles/f%02d.yaml", i)] = one
		}
		sha := g.Commit(t, files, "heavy")
		bin, log := loggingGit(t, "")
		if _, err := (CLI{Git: bin}).Files(ctx, Remote{URL: g.URL, Ref: "main"}, sha, []string{"bundles/*.yaml"}); !errors.Is(err, ErrTooLarge) || !strings.Contains(err.Error(), "together") {
			t.Fatalf("%d files of %d bytes: %v", len(files), len(one), err)
		}
		if l := readLog(t, log); strings.Contains(l, "cat-file blob") {
			t.Fatal("blobs were read although the set is over the total")
		}
	})
}

// A blob stream longer than its object's size (a misbehaving git) is cut at the bound: the
// command is stopped, not buffered to its end.
func TestBlobStreamIsCutAtTheBoundRound2(t *testing.T) {
	g := gittest.New(t, "", "")
	sha := g.Commit(t, map[string]string{"bundles/a.yaml": "x: 1\n"}, "small")
	bin, _ := loggingGit(t, "yes 0123456789abcdef")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	start := time.Now()
	_, err := CLI{Git: bin}.Files(ctx, Remote{URL: g.URL, Ref: "main"}, sha, []string{"bundles/*.yaml"})
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("an endless blob: %v", err)
	}
	if time.Since(start) > 20*time.Second {
		t.Fatalf("the endless blob ran for %s", time.Since(start))
	}
}
