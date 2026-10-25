package gitsync

import (
	"testing"

	"agent-sandbox/internal/gitsync/gittest"
)

// Resolve promises branch precedence when a branch and a tag share a name.
// Files must read that same branch, including when the tag points elsewhere.
func TestReviewGitBranchAndTagWithSameName(t *testing.T) {
	g := gittest.New(t, "", "")
	old := g.Commit(t, map[string]string{"bundle.yaml": "old\n"}, "old")
	head := g.Commit(t, map[string]string{"bundle.yaml": "current\n"}, "current")
	gittest.Git(t, g.Work, "tag", "main", old)
	gittest.Git(t, g.Work, "push", "-q", "origin", "refs/tags/main:refs/tags/main")
	remote := Remote{URL: g.URL, Ref: "main"}
	cli := CLI{}
	resolved, err := cli.Resolve(t.Context(), remote)
	if err != nil || resolved != head {
		t.Fatalf("resolve: head=%s err=%v", resolved, err)
	}
	files, err := cli.Files(t.Context(), remote, resolved, []string{"bundle.yaml"})
	if err != nil || string(files["bundle.yaml"]) != "current\n" {
		t.Fatalf("Files must use the same branch as Resolve: files=%v err=%v", files, err)
	}
}
