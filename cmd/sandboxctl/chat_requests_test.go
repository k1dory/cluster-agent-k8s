package main

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/k1dory/acpx"

	"agent-sandbox/internal/harness"
	"agent-sandbox/internal/model"
)

func reqMsg(role string, l harness.ACPLine) model.Message {
	b, _ := json.Marshal(l)
	return model.Message{Role: role, Data: b}
}

// The chat keeps the open requests and the agent's commands from the conversation, answers the
// latest request (or the one named), and lists both kinds of commands.
func TestChatStateFollowsRequestsAndCommands(t *testing.T) {
	s := newChatState()
	perm := acpx.Request{ID: "req_aaaaaaaaaaaaaaaa", Kind: acpx.RequestPermission, Title: "Edit", Options: []acpx.Option{{ID: "yes", Name: "Allow", Kind: "allow_once"}, {ID: "no", Name: "Reject", Kind: "reject_once"}}}
	form := acpx.Request{ID: "req_bbbbbbbbbbbbbbbb", Kind: acpx.RequestForm, Message: "Which db?", Schema: json.RawMessage(`{"type":"object","properties":{"db":{"type":"string","oneOf":[{"const":"pg"},{"const":"mysql"}]},"n":{"type":"integer"}},"required":["db"]}`)}
	s.observe(reqMsg(model.RoleRequest, harness.ACPLine{Type: harness.ACPRequest, Request: &perm}))
	s.observe(reqMsg(model.RoleRequest, harness.ACPLine{Type: harness.ACPRequest, Request: &form}))
	s.observe(reqMsg(model.RoleCommands, harness.ACPLine{Type: harness.ACPCommands, Commands: []harness.ACPCommand{{Name: "review", Hint: "branch", Description: "Review"}}}))

	if r, err := s.request(""); err != nil || r.ID != form.ID {
		t.Fatalf("latest: %+v %v", r, err)
	}
	if r, err := s.request(perm.ID); err != nil || r.ID != perm.ID {
		t.Fatalf("named: %+v %v", r, err)
	}
	s.observe(reqMsg(model.RoleResolved, harness.ACPLine{Type: harness.ACPResolved, RequestID: form.ID, Outcome: "accept", By: "user"}))
	if r, _ := s.request(""); r.ID != perm.ID {
		t.Fatalf("after the form was answered: %+v", r)
	}
	s.observe(reqMsg(model.RoleResolved, harness.ACPLine{Type: harness.ACPResolved, RequestID: perm.ID}))
	if _, err := s.request(""); err == nil {
		t.Fatal("nothing open")
	}
	if h := s.help(); !strings.Contains(h, "/reply") || !strings.Contains(h, "/review <branch> — Review") || !strings.Contains(h, "@path") {
		t.Fatalf("help: %s", h)
	}
	for _, want := range []string{"1. Allow (allow_once)", "/reply <number>"} {
		if !strings.Contains(renderRequest(perm), want) {
			t.Fatalf("permission view: %s", renderRequest(perm))
		}
	}
	if v := renderRequest(form); !strings.Contains(v, "db: pg | mysql  (required)") || !strings.Contains(v, "n: integer") {
		t.Fatalf("form view: %s", v)
	}
}

// /reply's answer: an option number or id, field=value pairs (JSON values as JSON), nothing for
// a link; an optional request id first.
func TestBuildReply(t *testing.T) {
	perm := acpx.Request{Kind: acpx.RequestPermission, Options: []acpx.Option{{ID: "yes"}, {ID: "no"}}}
	for args, want := range map[string]string{"2": "no", "yes": "yes"} {
		if r, err := buildReply(perm, []string{args}); err != nil || r.OptionID != want {
			t.Fatalf("%s: %+v %v", args, r, err)
		}
	}
	for _, bad := range [][]string{{"3"}, {"0"}, {"maybe"}, {}, {"1", "2"}} {
		if _, err := buildReply(perm, bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
	id, args := replyArgs(`req_0123456789abcdef db=pg n=3 tags=["a","b"] note="two words" flag=true`)
	if id != "req_0123456789abcdef" {
		t.Fatalf("id: %q", id)
	}
	r, err := buildReply(acpx.Request{Kind: acpx.RequestForm}, args)
	want := map[string]any{"db": "pg", "n": float64(3), "tags": []any{"a", "b"}, "note": "two words", "flag": true}
	if err != nil || r.Action != acpx.ActionAccept || !reflect.DeepEqual(r.Content, want) {
		t.Fatalf("form: %+v %v", r.Content, err)
	}
	if _, err := buildReply(acpx.Request{Kind: acpx.RequestForm}, []string{"novalue"}); err == nil {
		t.Fatal("field without =")
	}
	if r, err := buildReply(acpx.Request{Kind: acpx.RequestURL}, nil); err != nil || r.Action != acpx.ActionAccept {
		t.Fatalf("url: %+v %v", r, err)
	}
}

// @path names a workspace file to attach; an e-mail address or a trailing comma is not part of it.
func TestMentions(t *testing.T) {
	got := mentions("look at @repo/main.go and @/workspace/uploads/spec.md, also @./notes.txt; mail me at lev@example.com, @repo/main.go again")
	if want := []string{"repo/main.go", "uploads/spec.md", "notes.txt"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("mentions: %q", got)
	}
	if got := mentions("no files here"); got != nil {
		t.Fatalf("none: %q", got)
	}
}
