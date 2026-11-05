package acpx

import (
	"bytes"
	"encoding/json"
	"io"
	"sync"
	"sync/atomic"
)

// SystemPromptMetaKey marks a session request's system prompt: the text, in the request's _meta.
// The Wire moves it to the request's systemPrompt (append) and it never reaches the agent as
// metadata. acp-go-sdk v0.13.5 has no systemPrompt field.
const SystemPromptMetaKey = "agent-sandbox/systemPrompt"

// MaxLine is the longest line the Wire looks at: the connection's own limit (acp-go-sdk reads
// lines with a 10 MiB bufio.Scanner and cannot take a longer one). However the agent's output is
// cut into reads, a line up to it is looked at whole and a longer one not at all.
const MaxLine = 10 << 20

// WireOptions says what the client advertises beyond the SDK's ClientCapabilities and where the
// session updates the SDK cannot decode go.
type WireOptions struct {
	// Notices and Compaction advertise clientCapabilities.session.notices / .compaction in
	// initialize: an agent sends notice, compaction_update and compaction_summary_chunk only to a
	// client that does.
	Notices, Compaction bool
	// OnUpdate receives those updates. It runs on the reading goroutine, before the SDK has
	// processed the lines that came earlier: an update's place among the SDK's own is not exact.
	OnUpdate func(ExtraUpdate)
}

// Wire sits between the SDK's connection and the agent's stdio (Writer: to the agent, Reader:
// from it). Every byte passes through unchanged except the client's initialize request (the
// session capabilities) and a session request carrying SystemPromptMetaKey.
type Wire struct {
	w    io.Writer
	r    io.Reader
	opts WireOptions

	systemPrompt atomic.Bool // the agent declared sessionCapabilities.systemPrompt
	steering     atomic.Bool // the agent declared _meta.steering.supported
	initialized  atomic.Bool // the initialize response has gone by

	mu   sync.Mutex
	buf  []byte
	skip bool // the current line is longer than MaxLine: ignored up to its newline
}

// NewWire layers a Wire over the agent's stdin (w) and stdout (r).
func NewWire(agentStdin io.Writer, agentStdout io.Reader, opts WireOptions) *Wire {
	return &Wire{w: agentStdin, r: agentStdout, opts: opts}
}

// SystemPrompt reports whether the agent takes the client's system prompt
// (sessionCapabilities.systemPrompt in its initialize response).
func (x *Wire) SystemPrompt() bool { return x.systemPrompt.Load() }

// Steering reports whether the agent takes _session/steering (initialize _meta.steering.supported).
func (x *Wire) Steering() bool { return x.steering.Load() }

// Read passes the agent's output to the connection, looking at every line on the way. A line is
// looked at before the bytes that end it are returned, so what initialize declared is known by the
// time Initialize returns.
func (x *Wire) Read(p []byte) (int, error) {
	n, err := x.r.Read(p)
	if n > 0 {
		x.sniff(p[:n])
	}
	return n, err
}

func (x *Wire) sniff(b []byte) {
	x.mu.Lock()
	defer x.mu.Unlock()
	for len(b) > 0 {
		i := bytes.IndexByte(b, '\n')
		part := b
		if i >= 0 {
			part = b[:i]
		}
		if !x.skip {
			if len(x.buf)+len(part) > MaxLine {
				x.buf, x.skip = x.buf[:0], true
			} else {
				x.buf = append(x.buf, part...)
			}
		}
		if i < 0 {
			return
		}
		if !x.skip {
			x.inspect(bytes.TrimSuffix(x.buf, []byte("\r")))
		}
		x.buf, x.skip = x.buf[:0], false
		b = b[i+1:]
		if cap(x.buf) > 1<<20 && len(b) == 0 {
			x.buf = nil // do not keep a large line's buffer for the life of the agent
		}
	}
}

// inspect looks at one line from the agent: the initialize response (until it has gone by) and
// the session updates the SDK cannot decode.
func (x *Wire) inspect(line []byte) {
	if !x.initialized.Load() && bytes.Contains(line, []byte(`"protocolVersion"`)) {
		x.inspectInitialize(line)
	}
	if x.opts.OnUpdate != nil && bytes.Contains(line, []byte(`"session/update"`)) {
		if u, ok := decodeExtraUpdate(line); ok {
			x.opts.OnUpdate(u)
		}
	}
}

func (x *Wire) inspectInitialize(line []byte) {
	var msg struct {
		Result *struct {
			ProtocolVersion   json.RawMessage `json:"protocolVersion"`
			AgentCapabilities struct {
				SessionCapabilities struct {
					SystemPrompt json.RawMessage `json:"systemPrompt"`
				} `json:"sessionCapabilities"`
			} `json:"agentCapabilities"`
			Meta struct {
				Steering struct {
					Supported bool `json:"supported"`
				} `json:"steering"`
			} `json:"_meta"`
		} `json:"result"`
	}
	if json.Unmarshal(line, &msg) != nil || msg.Result == nil || msg.Result.ProtocolVersion == nil {
		return
	}
	x.systemPrompt.Store(present(msg.Result.AgentCapabilities.SessionCapabilities.SystemPrompt))
	x.steering.Store(msg.Result.Meta.Steering.Supported)
	x.initialized.Store(true)
}

// present: a capability object that is there (not absent, null or false).
func present(raw json.RawMessage) bool {
	v := bytes.TrimSpace(raw)
	return len(v) > 0 && !bytes.Equal(v, []byte("null")) && !bytes.Equal(v, []byte("false"))
}

// Write passes the client's messages to the agent. The connection writes one whole message per
// call; initialize and a session request with the system prompt marker are rewritten.
func (x *Wire) Write(b []byte) (int, error) {
	out, rewritten := b, false
	switch {
	case (x.opts.Notices || x.opts.Compaction) && bytes.Contains(b, []byte(`"method":"initialize"`)):
		out, rewritten = x.withSessionCapabilities(b)
	case bytes.Contains(b, []byte(SystemPromptMetaKey)):
		out, rewritten = withSystemPrompt(b)
	}
	if !rewritten {
		return x.w.Write(b)
	}
	if _, err := x.w.Write(out); err != nil {
		return 0, err
	}
	return len(b), nil
}

// withSessionCapabilities adds clientCapabilities.session.{notices,compaction} to initialize.
func (x *Wire) withSessionCapabilities(b []byte) ([]byte, bool) {
	return rewriteParams(b, "initialize", func(params map[string]json.RawMessage) bool {
		var caps map[string]json.RawMessage
		if raw, ok := params["clientCapabilities"]; ok && json.Unmarshal(raw, &caps) != nil {
			return false
		}
		if caps == nil {
			caps = map[string]json.RawMessage{}
		}
		session := map[string]json.RawMessage{}
		if raw, ok := caps["session"]; ok && !bytes.Equal(bytes.TrimSpace(raw), []byte("null")) && json.Unmarshal(raw, &session) != nil {
			return false
		}
		if x.opts.Notices {
			session["notices"] = json.RawMessage(`{}`)
		}
		if x.opts.Compaction {
			session["compaction"] = json.RawMessage(`{}`)
		}
		caps["session"], _ = json.Marshal(session)
		params["clientCapabilities"], _ = json.Marshal(caps)
		return true
	})
}

// withSystemPrompt moves the marker out of params._meta into params.systemPrompt (mode append,
// one text block).
func withSystemPrompt(b []byte) ([]byte, bool) {
	return rewriteParams(b, "", func(params map[string]json.RawMessage) bool {
		var meta map[string]json.RawMessage
		if json.Unmarshal(params["_meta"], &meta) != nil {
			return false
		}
		var text string
		if json.Unmarshal(meta[SystemPromptMetaKey], &text) != nil {
			return false
		}
		delete(meta, SystemPromptMetaKey)
		if len(meta) == 0 {
			delete(params, "_meta")
		} else {
			params["_meta"], _ = json.Marshal(meta)
		}
		params["systemPrompt"], _ = json.Marshal(map[string]any{
			"mode":    "append",
			"content": []map[string]string{{"type": "text", "text": text}},
		})
		return true
	})
}

// rewriteParams decodes one JSON-RPC message, lets edit change its params (method: only that
// method, "" any) and encodes it again; ok is false when nothing was changed.
func rewriteParams(b []byte, method string, edit func(map[string]json.RawMessage) bool) ([]byte, bool) {
	var msg map[string]json.RawMessage
	if json.Unmarshal(b, &msg) != nil {
		return nil, false
	}
	if method != "" {
		var m string
		if json.Unmarshal(msg["method"], &m) != nil || m != method {
			return nil, false
		}
	}
	params := map[string]json.RawMessage{}
	if raw, ok := msg["params"]; ok && json.Unmarshal(raw, &params) != nil {
		return nil, false
	}
	if !edit(params) {
		return nil, false
	}
	msg["params"], _ = json.Marshal(params)
	out, err := json.Marshal(msg)
	if err != nil {
		return nil, false
	}
	return append(out, '\n'), true
}
