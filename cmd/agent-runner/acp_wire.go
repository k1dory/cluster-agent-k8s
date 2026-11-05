package main

import (
	"bytes"
	"encoding/json"
	"io"
	"sync"
	"sync/atomic"
)

// The ACP system prompt (sessionCapabilities.systemPrompt in initialize, systemPrompt in
// session/new, load and resume: the agent appends the client's text to its own system prompt)
// is newer than acp-go-sdk v0.13.5, whose typed messages drop both. acpWire carries it at the
// JSON-RPC level until the SDK has the fields: it reads the capability off the agent's
// initialize response and turns a marker the runner puts in a session request's _meta into
// the request's systemPrompt. Everything else passes through unchanged.
//
// Without the capability the runner never sets the marker and the instructions go ahead of
// the first prompt as before (firstPrompt).

// systemPromptMetaKey is the marker: the instructions, in the _meta of session/new, load or
// resume. It never reaches the agent.
const systemPromptMetaKey = "agent-sandbox/systemPrompt"

// maxSniffLine bounds what the reader keeps of one line while it looks for the initialize
// response; a longer line is not it.
const maxSniffLine = 1 << 20

type acpWire struct {
	w io.Writer
	r io.Reader

	systemPrompt atomic.Bool // the agent declared sessionCapabilities.systemPrompt
	done         atomic.Bool // the initialize response has been seen: stop looking

	mu  sync.Mutex
	buf []byte
}

func newACPWire(agentStdin io.Writer, agentStdout io.Reader) *acpWire {
	return &acpWire{w: agentStdin, r: agentStdout}
}

// SystemPrompt reports whether the agent takes the client's system prompt.
func (x *acpWire) SystemPrompt() bool { return x.systemPrompt.Load() }

// Read passes the agent's output to the connection, looking at each line until the initialize
// response has gone by. A line is looked at before the bytes that end it are returned, so the
// capability is known by the time Initialize returns.
func (x *acpWire) Read(p []byte) (int, error) {
	n, err := x.r.Read(p)
	if n > 0 && !x.done.Load() {
		x.sniff(p[:n])
	}
	return n, err
}

func (x *acpWire) sniff(b []byte) {
	x.mu.Lock()
	defer x.mu.Unlock()
	for len(b) > 0 && !x.done.Load() {
		i := bytes.IndexByte(b, '\n')
		if i < 0 {
			if len(x.buf)+len(b) <= maxSniffLine {
				x.buf = append(x.buf, b...)
			} else {
				x.buf = x.buf[:0]
			}
			return
		}
		line := b[:i]
		if len(x.buf) > 0 {
			line = append(x.buf, line...)
		}
		x.inspect(line)
		x.buf = x.buf[:0]
		b = b[i+1:]
	}
}

// inspect looks for the initialize response: a result with protocolVersion and
// agentCapabilities.
func (x *acpWire) inspect(line []byte) {
	if !bytes.Contains(line, []byte(`"protocolVersion"`)) {
		return
	}
	var msg struct {
		Result *struct {
			ProtocolVersion   json.RawMessage `json:"protocolVersion"`
			AgentCapabilities struct {
				SessionCapabilities struct {
					SystemPrompt json.RawMessage `json:"systemPrompt"`
				} `json:"sessionCapabilities"`
			} `json:"agentCapabilities"`
		} `json:"result"`
	}
	if json.Unmarshal(line, &msg) != nil || msg.Result == nil || msg.Result.ProtocolVersion == nil {
		return
	}
	sp := bytes.TrimSpace(msg.Result.AgentCapabilities.SessionCapabilities.SystemPrompt)
	x.systemPrompt.Store(len(sp) > 0 && !bytes.Equal(sp, []byte("null")) && !bytes.Equal(sp, []byte("false")))
	x.done.Store(true)
}

// Write passes the runner's messages to the agent. The connection writes one whole message per
// call; one carrying the marker is rewritten.
func (x *acpWire) Write(b []byte) (int, error) {
	if bytes.Contains(b, []byte(systemPromptMetaKey)) {
		if out, ok := withSystemPrompt(b); ok {
			if _, err := x.w.Write(out); err != nil {
				return 0, err
			}
			return len(b), nil
		}
	}
	return x.w.Write(b)
}

// withSystemPrompt moves the marker out of params._meta into params.systemPrompt (mode append,
// one text block). ok is false for anything that is not such a message.
func withSystemPrompt(b []byte) ([]byte, bool) {
	var msg map[string]json.RawMessage
	if json.Unmarshal(b, &msg) != nil {
		return nil, false
	}
	var params map[string]json.RawMessage
	if json.Unmarshal(msg["params"], &params) != nil {
		return nil, false
	}
	var meta map[string]json.RawMessage
	if json.Unmarshal(params["_meta"], &meta) != nil {
		return nil, false
	}
	var text string
	if json.Unmarshal(meta[systemPromptMetaKey], &text) != nil {
		return nil, false
	}
	delete(meta, systemPromptMetaKey)
	if len(meta) == 0 {
		delete(params, "_meta")
	} else {
		params["_meta"], _ = json.Marshal(meta)
	}
	params["systemPrompt"], _ = json.Marshal(map[string]any{
		"mode":    "append",
		"content": []map[string]string{{"type": "text", "text": text}},
	})
	msg["params"], _ = json.Marshal(params)
	out, err := json.Marshal(msg)
	if err != nil {
		return nil, false
	}
	return append(out, '\n'), true
}
