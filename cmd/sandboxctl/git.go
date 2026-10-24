package main

import (
	"bytes"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"

	"agent-sandbox/internal/apply"
)

// bundleSource is the Git provenance sandboxctl attaches to an apply (the API's `source`).
type bundleSource struct {
	Repo   string `json:"repo,omitempty"`
	Ref    string `json:"ref,omitempty"`
	Commit string `json:"commit,omitempty"`
	Path   string `json:"path,omitempty"`
}

// gitSource describes the commit a bundle file matches. content is what will be applied (the
// bytes read from the file). ok is false when the file is not in a Git work tree (or git is not
// installed). dirty says those bytes are not what HEAD holds for the path, or the file is
// untracked: the source then carries repo, ref and path but no commit, so a recorded SHA always
// names exactly the content that was applied. The comparison is on the bytes themselves, not on
// `git status`: an index marked assume-unchanged or skip-worktree reports clean while the file
// differs, and would otherwise attribute foreign content to a commit.
func gitSource(file string, content []byte) (src bundleSource, ok, dirty bool, err error) {
	abs, err := filepath.Abs(file)
	if err != nil {
		return src, false, false, err
	}
	dir := filepath.Dir(abs)
	gitRaw := func(args ...string) ([]byte, error) {
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		var out, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &stderr
		if err := cmd.Run(); err != nil {
			return nil, errors.New(strings.TrimSpace(stderr.String()))
		}
		return out.Bytes(), nil
	}
	git := func(args ...string) (string, error) {
		out, err := gitRaw(args...)
		return strings.TrimSpace(string(out)), err
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
	remote, _ := git("remote", "get-url", "origin")
	if src.Repo, err = apply.StripCredentials(remote); err != nil {
		src.Repo = "" // an unparsable remote is not worth recording
	}
	path, err := git("ls-files", "--full-name", "--error-unmatch", "--", abs)
	if err != nil {
		return src, true, true, nil // untracked
	}
	src.Path = path
	committed, err := gitRaw("cat-file", "blob", "HEAD:"+path)
	if err != nil || !bytes.Equal(committed, content) {
		return src, true, true, nil // staged but not committed, or the bytes differ from HEAD
	}
	src.Commit = head
	return src, true, false, nil
}
