package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/k1dory/acpx"

	"agent-sandbox/internal/harness"
	"agent-sandbox/internal/model"
)

// chatState is what the chat keeps from the conversation: the agent's requests still waiting
// for an answer and the commands the agent offers. Both come in the conversation itself (roles
// request, resolved, commands; their data is the runner's line), so any client builds the same
// from the stream: this one is the reference.
type chatState struct {
	mu       sync.Mutex
	open     map[string]openRequest
	order    []string // open requests, oldest first
	commands []harness.ACPCommand
}

// openRequest is a request and the run that asked it (the answer goes to that run).
type openRequest struct {
	acpx.Request
	RunID string
}

func newChatState() *chatState { return &chatState{open: map[string]openRequest{}} }

// observe takes in one turn of the conversation.
func (s *chatState) observe(m model.Message) {
	if len(m.Data) == 0 {
		return
	}
	var l harness.ACPLine
	if json.Unmarshal(m.Data, &l) != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case m.Role == model.RoleRequest && l.Request != nil:
		s.open[l.Request.ID] = openRequest{Request: *l.Request, RunID: m.RunID}
		s.order = append(s.order, l.Request.ID)
	case m.Role == model.RoleResolved:
		delete(s.open, l.RequestID)
		for i, id := range s.order {
			if id == l.RequestID {
				s.order = append(s.order[:i], s.order[i+1:]...)
				break
			}
		}
	case m.Role == model.RoleCommands:
		s.commands = l.Commands
	}
}

// request is the open request a reply means: the one named, else the latest.
func (s *chatState) request(id string) (openRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id != "" {
		if r, ok := s.open[id]; ok {
			return r, nil
		}
		return openRequest{}, fmt.Errorf("no open request %s", id)
	}
	if len(s.order) == 0 {
		return openRequest{}, errors.New("the agent is not waiting for an answer")
	}
	return s.open[s.order[len(s.order)-1]], nil
}

// help lists the chat's own commands and the agent's.
func (s *chatState) help() string {
	var b strings.Builder
	b.WriteString("chat: /attach <file>, /files [path], /reply [request] <answer>, /decline [request], /cancel [request], /close, /quit\n")
	b.WriteString("      @path in a message attaches a workspace file (uploads/report.pdf, repo/main.go)\n")
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.commands) == 0 {
		b.WriteString("agent: no commands announced yet\n")
		return b.String()
	}
	b.WriteString("agent:\n")
	for _, c := range s.commands {
		line := "  /" + c.Name
		if c.Hint != "" {
			line += " <" + c.Hint + ">"
		}
		if c.Description != "" {
			line += " — " + c.Description
		}
		b.WriteString(line + "\n")
	}
	return b.String()
}

// renderRequest shows what the agent asks and how to answer it.
func renderRequest(r acpx.Request) string {
	var b strings.Builder
	switch r.Kind {
	case acpx.RequestPermission:
		fmt.Fprintf(&b, "? the agent asks permission: %s  [%s]\n", r.Title, r.ID)
		if r.Text != "" {
			b.WriteString("    " + strings.ReplaceAll(truncateText(r.Text, 2000), "\n", "\n    ") + "\n")
		}
		if len(r.RawInput) > 0 && string(r.RawInput) != "{}" {
			fmt.Fprintf(&b, "    input: %s\n", truncateText(string(r.RawInput), 500))
		}
		for i, o := range r.Options {
			fmt.Fprintf(&b, "    %d. %s (%s)\n", i+1, o.Name, o.Kind)
		}
		b.WriteString("    answer: /reply <number>   or /decline")
	case acpx.RequestForm:
		fmt.Fprintf(&b, "? the agent asks: %s  [%s]\n", r.Message, r.ID)
		for _, f := range formFields(r.Schema) {
			b.WriteString("    " + f + "\n")
		}
		b.WriteString("    answer: /reply field=value …   or /decline")
	case acpx.RequestURL:
		fmt.Fprintf(&b, "? the agent asks you to open: %s\n    %s  [%s]\n", r.Message, r.URL, r.ID)
		b.WriteString("    when done: /reply   or /decline")
	default:
		fmt.Fprintf(&b, "? the agent asks (%s)  [%s]", r.Kind, r.ID)
	}
	return b.String()
}

// formFields describes a form's fields: name, title, the question (description), choices
// (oneOf/anyOf/enum, or a multi-select's items), required.
func formFields(schema json.RawMessage) []string {
	type choices struct {
		Type  string `json:"type"`
		OneOf []struct {
			Const any `json:"const"`
		} `json:"oneOf"`
		AnyOf []struct {
			Const any `json:"const"`
		} `json:"anyOf"`
		Enum []any `json:"enum"`
	}
	var s struct {
		Properties map[string]struct {
			choices
			Title       string   `json:"title"`
			Description string   `json:"description"`
			Items       *choices `json:"items"`
		} `json:"properties"`
		Required []string `json:"required"`
	}
	if json.Unmarshal(schema, &s) != nil {
		return nil
	}
	list := func(c choices) []string {
		var out []string
		for _, o := range append(c.OneOf, c.AnyOf...) {
			out = append(out, fmt.Sprint(o.Const))
		}
		for _, e := range c.Enum {
			out = append(out, fmt.Sprint(e))
		}
		return out
	}
	required := map[string]bool{}
	for _, r := range s.Required {
		required[r] = true
	}
	names := make([]string, 0, len(s.Properties))
	for n := range s.Properties {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []string
	for _, n := range names {
		p := s.Properties[n]
		line := n
		if p.Title != "" {
			line += " (" + p.Title + ")"
		}
		if p.Description != "" {
			line += " — " + p.Description
		}
		switch {
		case p.Items != nil && len(list(*p.Items)) > 0:
			line += ": any of " + strings.Join(list(*p.Items), " | ") + "  (field='[\"a\",\"b\"]')"
		case len(list(p.choices)) > 0:
			line += ": " + strings.Join(list(p.choices), " | ")
		case p.Type != "":
			line += ": " + p.Type
		}
		if required[n] {
			line += "  (required)"
		}
		out = append(out, line)
	}
	return out
}

func truncateText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// buildReply turns what was typed after /reply into the answer to r: an option's number or id
// for a permission, field=value pairs for a form (a value that reads as JSON is taken as such:
// numbers, true/false, ["a","b"]), nothing for a link.
func buildReply(r acpx.Request, args []string) (acpx.Reply, error) {
	switch r.Kind {
	case acpx.RequestPermission:
		if len(args) != 1 {
			return acpx.Reply{}, errors.New("/reply <option number>")
		}
		if n, err := strconv.Atoi(args[0]); err == nil {
			if n < 1 || n > len(r.Options) {
				return acpx.Reply{}, fmt.Errorf("option %d: the request offers %d", n, len(r.Options))
			}
			return acpx.Reply{OptionID: r.Options[n-1].ID}, nil
		}
		for _, o := range r.Options {
			if o.ID == args[0] {
				return acpx.Reply{OptionID: o.ID}, nil
			}
		}
		return acpx.Reply{}, fmt.Errorf("no option %q", args[0])
	case acpx.RequestForm:
		content := map[string]any{}
		for _, a := range args {
			k, v, ok := strings.Cut(a, "=")
			if !ok || k == "" {
				return acpx.Reply{}, fmt.Errorf("%q: field=value", a)
			}
			var parsed any
			if json.Unmarshal([]byte(v), &parsed) == nil {
				content[k] = parsed
			} else {
				content[k] = v
			}
		}
		return acpx.Reply{Action: acpx.ActionAccept, Content: content}, nil
	case acpx.RequestURL:
		return acpx.Reply{Action: acpx.ActionAccept}, nil
	}
	return acpx.Reply{}, fmt.Errorf("cannot answer a %s request", r.Kind)
}

// replyArgs splits what follows /reply: an optional request id first, then the answer. Form
// values may be quoted: field="two words".
func replyArgs(s string) (id string, args []string) {
	args = splitReplyArgs(s)
	if len(args) > 0 && strings.HasPrefix(args[0], "req_") {
		return args[0], args[1:]
	}
	return "", args
}

// splitReplyArgs splits on spaces outside quotes and brackets: field="two words" and
// tags=["a", "b"] stay one argument each.
func splitReplyArgs(s string) []string {
	var out []string
	var cur strings.Builder
	depth, quoted, escaped := 0, false, false
	for _, r := range s {
		switch {
		case escaped:
			escaped = false
		case quoted && r == '\\':
			escaped = true
		case r == '"':
			quoted = !quoted
		case !quoted && (r == '[' || r == '{'):
			depth++
		case !quoted && (r == ']' || r == '}') && depth > 0:
			depth--
		case !quoted && depth == 0 && (r == ' ' || r == '\t'):
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
			continue
		}
		cur.WriteRune(r)
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// mentionRe finds @path mentions: a workspace path after @ at the start of a word.
var mentionRe = regexp.MustCompile(`(?:^|\s)@([A-Za-z0-9._/-]+)`)

// mentions are the workspace files a message names with @path; the text is sent as typed and the
// files are attached (the agent gets them as files).
func mentions(text string) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range mentionRe.FindAllStringSubmatch(text, -1) {
		p := strings.TrimPrefix(strings.TrimPrefix(m[1], "/workspace/"), "./")
		p = strings.TrimRight(p, ".,;:)")
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}
