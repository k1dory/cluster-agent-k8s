package acpx

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

// The Wire reads the capability off the initialize response and turns the marker into the
// request's systemPrompt; the rest of the request and every other message pass unchanged.
func TestACPWireSystemPrompt(t *testing.T) {
	var sent bytes.Buffer
	init := `{"jsonrpc":"2.0","id":0,"result":{"protocolVersion":1,"agentCapabilities":{"sessionCapabilities":{"resume":{},"systemPrompt":{"mode":{"override":{}}}}}}}` + "\n"
	w := NewWire(&sent, strings.NewReader(`{"jsonrpc":"2.0","method":"session/update","params":{}}`+"\n"+init[:40]), WireOptions{})
	buf := make([]byte, 7) // lines arrive in pieces
	for {
		if _, err := w.Read(buf); err != nil {
			break
		}
	}
	if w.SystemPrompt() {
		t.Fatal("capability before the initialize response")
	}
	w.r = strings.NewReader(init[40:])
	for {
		if _, err := w.Read(buf); err != nil {
			break
		}
	}
	if !w.SystemPrompt() {
		t.Fatal("capability not seen")
	}
	none := NewWire(&sent, strings.NewReader(`{"jsonrpc":"2.0","id":0,"result":{"protocolVersion":1,"agentCapabilities":{"loadSession":true}}}`+"\n"), WireOptions{})
	_, _ = none.Read(make([]byte, 4096))
	if none.SystemPrompt() {
		t.Fatal("capability without systemPrompt")
	}

	req, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "session/new",
		"params": map[string]any{"cwd": "/w", "mcpServers": []any{}, "_meta": map[string]any{SystemPromptMetaKey: "Be brief.", "other": 1}}})
	if n, err := w.Write(append(req, '\n')); err != nil || n != len(req)+1 {
		t.Fatalf("write: %d %v", n, err)
	}
	var got struct {
		Params map[string]json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(sent.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if string(got.Params["systemPrompt"]) != `{"content":[{"text":"Be brief.","type":"text"}],"mode":"append"}` ||
		string(got.Params["_meta"]) != `{"other":1}` || string(got.Params["cwd"]) != `"/w"` {
		t.Fatalf("rewritten: %s", sent.String())
	}
	sent.Reset()
	plain := `{"jsonrpc":"2.0","id":2,"method":"session/prompt","params":{}}` + "\n"
	_, _ = w.Write([]byte(plain))
	if sent.String() != plain {
		t.Fatalf("passthrough: %q", sent.String())
	}
}

// chunkedReader returns at most n bytes per Read, as a pipe may.
type chunkedReader struct {
	r io.Reader
	n int
}

func (c chunkedReader) Read(p []byte) (int, error) {
	if len(p) > c.n {
		p = p[:c.n]
	}
	return c.r.Read(p)
}

// The capability is read off the initialize response however the agent's output is cut into
// reads: byte by byte, CRLF, among other lines, after an over-long line, and a large response
// (up to the connection's own line limit) whole or in pieces. A line over the limit is ignored
// whole in every cutting (the connection cannot read it either). The bytes pass unchanged.
func TestACPWireCapabilityDoesNotDependOnReads(t *testing.T) {
	init := `{"jsonrpc":"2.0","id":0,"result":{"protocolVersion":1,"agentCapabilities":{"sessionCapabilities":{"systemPrompt":{"mode":{"override":{}}}}}}}`
	padded := func(n int) string {
		return `{"jsonrpc":"2.0","id":0,"result":{"_meta":{"padding":"` + strings.Repeat("x", n) +
			`"},"protocolVersion":1,"agentCapabilities":{"sessionCapabilities":{"systemPrompt":{}}}}}` + "\n"
	}
	large := padded(3 << 20)          // well over the old 1 MiB, under the limit
	tooLong := padded(MaxLine + 8192) // over the limit
	for _, tc := range []struct {
		name, input string
		want        bool
	}{
		{"bytes", init + "\n", true},
		{"crlf", init + "\r\n", true},
		{"among lines", "{}\n" + init + "\n{}\n", true},
		{"after an over-long line", strings.Repeat("x", MaxLine+8192) + "\n" + init + "\n", true},
		{"large", large, true},
		{"over the limit", tooLong, false},
		{"over the limit, then the real one", tooLong + init + "\n", true},
	} {
		for _, chunk := range []int{1, 7, 4096, 1 << 20, len(tc.input)} {
			if chunk == 1 && len(tc.input) > 1<<16 {
				continue // byte by byte is covered by the short inputs
			}
			w := NewWire(io.Discard, chunkedReader{strings.NewReader(tc.input), chunk}, WireOptions{})
			got, err := io.ReadAll(w)
			if err != nil || string(got) != tc.input {
				t.Fatalf("%s/%d: bytes changed (%v)", tc.name, chunk, err)
			}
			if w.SystemPrompt() != tc.want {
				t.Errorf("%s, reads of %d: capability %v, want %v", tc.name, chunk, w.SystemPrompt(), tc.want)
			}
		}
	}
}
