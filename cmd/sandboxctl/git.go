package main

import (
	"bytes"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
)

// bundleSource is the Git provenance sandboxctl attaches to an apply (the API's `source`).
type bundleSource struct {
	Repo   string `json:"repo,omitempty"`
	Ref    string `json:"ref,omitempty"`
	Commit string `json:"commit,omitempty"`
	Path   string `json:"path,omitempty"`
}

// gitSource describes the commit a bundle file matches. ok is false when the file is not in a
// Git work tree (or git is not installed). dirty says the file differs from its committed
// version or is untracked: the source then carries repo, ref and path but no commit, so a
// recorded SHA always names exactly the content that was applied.
func gitSource(file string) (src bundleSource, ok, dirty bool, err error) {
	abs, err := filepath.Abs(file)
	if err != nil {
		return src, false, false, err
	}
	dir := filepath.Dir(abs)
	git := func(args ...string) (string, error) {
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		var out, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &stderr
		if err := cmd.Run(); err != nil {
			return "", errors.New(strings.TrimSpace(stderr.String()))
		}
		return strings.TrimSpace(out.String()), nil
	}
	if _, err := exec.LookPath("git"); err != nil {
		return src, false, false, nil
	}
	if _, err := git("rev-parse", "--show-toplevel"); err != nil {
		return src, false, false, nil // not a work tree
	}
	head, err := git("rev-parse", "HEAD")
	if err != nil {
		return src, false, false, nil // no commits yet
	}
	src.Ref, _ = git("rev-parse", "--abbrev-ref", "HEAD")
	if src.Ref == "HEAD" {
		src.Ref = "" // detached: the commit says it all
	}
	src.Repo, _ = git("remote", "get-url", "origin")
	path, err := git("ls-files", "--full-name", "--error-unmatch", "--", abs)
	if err != nil {
		return src, true, true, nil // untracked
	}
	src.Path = path
	status, _ := git("status", "--porcelain", "--", abs)
	if status != "" {
		return src, true, true, nil
	}
	src.Commit = head
	return src, true, false, nil
}
