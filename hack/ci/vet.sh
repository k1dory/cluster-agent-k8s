#!/usr/bin/env bash
# ci-vet: go vet, and gofmt over the module's own Go files, listed by `go list` (never a
# module cache or a tool directory that happens to live inside the tree, such as GitLab's
# cached GOMODCACHE). gofmt's exit status counts: a formatter that fails without output is a
# failure, not a clean tree.
. "$(dirname "$0")/lib.sh"
cd "$ci_root"
go vet ./...
files=$(go list -f '{{$d := .Dir}}{{range .GoFiles}}{{$d}}/{{.}}{{"\n"}}{{end}}{{range .CgoFiles}}{{$d}}/{{.}}{{"\n"}}{{end}}{{range .TestGoFiles}}{{$d}}/{{.}}{{"\n"}}{{end}}{{range .XTestGoFiles}}{{$d}}/{{.}}{{"\n"}}{{end}}' ./...)
[ -n "$files" ] || ci_die "vet: go list found no Go files"
# shellcheck disable=SC2086
unformatted=$(gofmt -l $files) || ci_die "vet: gofmt failed"
[ -z "$unformatted" ] || ci_die "vet: not gofmt-formatted:
$unformatted"
ci_ok vet
