package harness

import (
	"reflect"
	"testing"

	"github.com/k1dory/acpx"
)

// The control plane writes the attached files after the text; the runner takes them apart again.
func TestAttachmentsRoundTrip(t *testing.T) {
	s := WithAttachments("review this", []string{"/workspace/uploads/a.md", "/workspace/repo/main.go"})
	text, paths := SplitAttachments(s)
	if text != "review this" || !reflect.DeepEqual(paths, []string{"/workspace/uploads/a.md", "/workspace/repo/main.go"}) {
		t.Fatalf("split: %q %q", text, paths)
	}
	if s := WithAttachments("", []string{"/workspace/a"}); s != "See the attached files.\n\nAttached files:\n- /workspace/a" {
		t.Fatalf("empty text: %q", s)
	}
	for _, plain := range []string{"just text", "text\n\nAttached files:\n- not a path", ""} {
		if text, paths := SplitAttachments(plain); text != plain || paths != nil {
			t.Fatalf("%q: %q %q", plain, text, paths)
		}
	}
	if WithAttachments("x", nil) != "x" {
		t.Fatal("no files")
	}
}

// The agent's requests, their resolution and its commands are turns of the conversation.
func TestParseMessageRequestsAndCommands(t *testing.T) {
	req := acpx.Request{ID: "req_1", Kind: acpx.RequestForm, Message: "Which db?"}
	for line, want := range map[string][2]string{
		ACPLine{Type: ACPRequest, Request: &req}.String():                                      {RoleRequest, "Which db?"},
		ACPLine{Type: ACPResolved, RequestID: "req_1", Outcome: "accept", By: "user"}.String(): {RoleResolved, "accept (user)"},
		ACPLine{Type: ACPCommands, Commands: []ACPCommand{{Name: "a"}, {Name: "b"}}}.String():  {RoleCommands, "/a /b"},
	} {
		if role, text := ParseMessage(line); role != want[0] || text != want[1] {
			t.Errorf("%s → %q %q", line, role, text)
		}
	}
}
