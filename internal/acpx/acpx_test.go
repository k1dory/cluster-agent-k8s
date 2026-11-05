package acpx

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"

	acp "github.com/coder/acp-go-sdk"
)

// initialize gains clientCapabilities.session.{notices,compaction} as asked; what the SDK put
// there stays, and nothing else is touched.
func TestWireAdvertisesSessionCapabilities(t *testing.T) {
	var sent bytes.Buffer
	w := NewWire(&sent, strings.NewReader(""), WireOptions{Notices: true, Compaction: true})
	req := `{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":1,"clientCapabilities":{"fs":{"readTextFile":false,"writeTextFile":false},"terminal":false}}}` + "\n"
	if n, err := w.Write([]byte(req)); err != nil || n != len(req) {
		t.Fatalf("write: %d %v", n, err)
	}
	var got struct {
		Params struct {
			ProtocolVersion    int `json:"protocolVersion"`
			ClientCapabilities struct {
				FS       map[string]bool            `json:"fs"`
				Terminal *bool                      `json:"terminal"`
				Session  map[string]json.RawMessage `json:"session"`
			} `json:"clientCapabilities"`
		} `json:"params"`
	}
	if err := json.Unmarshal(sent.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	c := got.Params.ClientCapabilities
	if got.Params.ProtocolVersion != 1 || c.Terminal == nil || len(c.FS) != 2 || string(c.Session["notices"]) != "{}" || string(c.Session["compaction"]) != "{}" {
		t.Fatalf("initialize: %s", sent.String())
	}
	// Without the options, initialize passes as it is; so does every other message.
	sent.Reset()
	plain := NewWire(&sent, strings.NewReader(""), WireOptions{})
	_, _ = plain.Write([]byte(req))
	if sent.String() != req {
		t.Fatalf("rewritten without options: %s", sent.String())
	}
	sent.Reset()
	other := `{"jsonrpc":"2.0","id":3,"method":"session/prompt","params":{"sessionId":"s","prompt":[]}}` + "\n"
	_, _ = w.Write([]byte(other))
	if sent.String() != other {
		t.Fatalf("prompt changed: %s", sent.String())
	}
}

// The Wire reads steering support off initialize's _meta, and hands over notices, compaction
// updates and summary chunks; other updates and malformed ones are not its business.
func TestWireReadsSteeringAndExtraUpdates(t *testing.T) {
	var got []ExtraUpdate
	lines := strings.Join([]string{
		`{"jsonrpc":"2.0","id":0,"result":{"protocolVersion":1,"agentCapabilities":{},"_meta":{"steering":{"supported":true}}}}`,
		`{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"s1","update":{"sessionUpdate":"notice","severity":"warning","title":"Rate limit near","description":"80% used"}}}`,
		`{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"s1","update":{"sessionUpdate":"compaction_update","compactionId":"c1","status":"in_progress"}}}`,
		`{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"s1","update":{"sessionUpdate":"compaction_summary_chunk","compactionId":"c1","content":{"type":"text","text":"so far"}}}}`,
		`{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"s1","update":{"sessionUpdate":"compaction_update","compactionId":"c1","status":"completed","summary":[{"type":"text","text":"done"}]}}}`,
		`{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"s1","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"hi"}}}}`,
		`{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"s1","update":{"sessionUpdate":"notice","severity":"info"}}}`,
	}, "\n") + "\n"
	w := NewWire(io.Discard, chunked{strings.NewReader(lines), 5}, WireOptions{OnUpdate: func(u ExtraUpdate) { got = append(got, u) }})
	if b, err := io.ReadAll(w); err != nil || string(b) != lines {
		t.Fatalf("bytes changed: %v", err)
	}
	switch {
	case !w.Steering() || w.SystemPrompt():
		t.Fatalf("capabilities: steering %v system prompt %v", w.Steering(), w.SystemPrompt())
	case len(got) != 4:
		t.Fatalf("updates: %+v", got)
	case got[0].SessionID != "s1" || got[0].Notice == nil || *got[0].Notice != (Notice{Severity: "warning", Title: "Rate limit near", Description: "80% used"}):
		t.Fatalf("notice: %+v", got[0])
	case got[1].Compaction == nil || got[1].Compaction.Status != "in_progress":
		t.Fatalf("compaction start: %+v", got[1])
	case got[2].SummaryChunk == nil || got[2].SummaryChunk.Text != "so far":
		t.Fatalf("summary chunk: %+v", got[2])
	case got[3].Compaction == nil || got[3].Compaction.Status != "completed" || got[3].Compaction.Summary != "done":
		t.Fatalf("compaction end: %+v", got[3])
	}
}

type chunked struct {
	r io.Reader
	n int
}

func (c chunked) Read(p []byte) (int, error) {
	if len(p) > c.n {
		p = p[:c.n]
	}
	return c.r.Read(p)
}

// steeringAgent is an ACP agent on the other end of a real connection: it advertises steering and
// answers _session/steering as claude-agent-acp does.
type steeringAgent struct {
	acp.Agent
	busy bool
	mu   sync.Mutex
	got  []map[string]any
}

func (a *steeringAgent) Initialize(context.Context, acp.InitializeRequest) (acp.InitializeResponse, error) {
	return acp.InitializeResponse{ProtocolVersion: acp.ProtocolVersionNumber, Meta: map[string]any{"steering": map[string]any{"supported": true}}}, nil
}

func (a *steeringAgent) HandleExtensionMethod(_ context.Context, method string, params json.RawMessage) (any, error) {
	if method != SteerMethod {
		return nil, errors.New("unknown")
	}
	var p map[string]any
	_ = json.Unmarshal(params, &p)
	a.mu.Lock()
	defer a.mu.Unlock()
	a.got = append(a.got, p)
	if !a.busy {
		return map[string]any{"outcome": "promptRequired", "reason": "noRunningTurn"}, nil
	}
	return map[string]any{"outcome": "injected"}, nil
}

// Steer goes to the agent as _session/steering with the text as a prompt and idleBehavior
// promptRequired; the outcome comes back. An agent that did not advertise steering is not asked.
func TestSteer(t *testing.T) {
	toAgent, agentIn := io.Pipe()
	agentOut, fromAgent := io.Pipe()
	agent := &steeringAgent{busy: true}
	acp.NewAgentSideConnection(agent, fromAgent, toAgent)
	conn := Dial(nopClient{}, agentIn, agentOut, WireOptions{})
	ctx := context.Background()
	if _, err := conn.Initialize(ctx, acp.InitializeRequest{ProtocolVersion: acp.ProtocolVersionNumber}); err != nil {
		t.Fatal(err)
	}
	out, err := conn.Steer(ctx, "s1", "also check the tests")
	if err != nil || out != SteerInjected {
		t.Fatalf("busy: %q %v", out, err)
	}
	agent.mu.Lock()
	agent.busy = false
	agent.mu.Unlock()
	if out, err := conn.Steer(ctx, "s1", "next"); err != nil || out != SteerPromptRequired {
		t.Fatalf("idle: %q %v", out, err)
	}
	agent.mu.Lock()
	defer agent.mu.Unlock()
	b, _ := json.Marshal(agent.got[0])
	if !strings.Contains(string(b), `"idleBehavior":"promptRequired"`) || !strings.Contains(string(b), `"text":"also check the tests"`) || !strings.Contains(string(b), `"sessionId":"s1"`) {
		t.Fatalf("request: %s", b)
	}

	plain := Dial(nopClient{}, io.Discard, strings.NewReader(""), WireOptions{})
	if out, err := plain.Steer(ctx, "s1", "x"); err != nil || out != SteerPromptRequired {
		t.Fatalf("without steering: %q %v", out, err)
	}
}

type nopClient struct{ acp.Client }

func (nopClient) SessionUpdate(context.Context, acp.SessionNotification) error { return nil }

type recordingConfigurer struct{ calls []string }

func (r *recordingConfigurer) SetSessionMode(_ context.Context, p acp.SetSessionModeRequest) (acp.SetSessionModeResponse, error) {
	r.calls = append(r.calls, "mode="+string(p.ModeId))
	return acp.SetSessionModeResponse{}, nil
}

func (r *recordingConfigurer) SetSessionConfigOption(_ context.Context, p acp.SetSessionConfigOptionRequest) (acp.SetSessionConfigOptionResponse, error) {
	r.calls = append(r.calls, string(p.ValueId.ConfigId)+"="+string(p.ValueId.Value))
	return acp.SetSessionConfigOptionResponse{}, nil
}

func option(id string, cat acp.SessionConfigOptionCategory, current string, values ...[2]string) acp.SessionConfigOption {
	opts := acp.SessionConfigSelectOptionsUngrouped{}
	for _, v := range values {
		opts = append(opts, acp.SessionConfigSelectOption{Value: acp.SessionConfigValueId(v[0]), Name: v[1]})
	}
	return acp.SessionConfigOption{Select: &acp.SessionConfigOptionSelect{Id: acp.SessionConfigId(id), Category: &cat,
		CurrentValue: acp.SessionConfigValueId(current), Options: acp.SessionConfigSelectOptions{Ungrouped: &opts}, Type: "select"}}
}

// The reasoning level is selected through the agent's thought_level option, by value or display
// name; an agent without one, or without the level, keeps its own and the caller is told.
func TestConfigureThoughtLevel(t *testing.T) {
	ctx := context.Background()
	st := SessionState{Options: []acp.SessionConfigOption{option("reasoning_effort", acp.SessionConfigOptionCategoryThoughtLevel, "medium",
		[2]string{"low", "Low"}, [2]string{"medium", "Medium"}, [2]string{"xhigh", "Extra high"})}}
	r := &recordingConfigurer{}
	for _, want := range []string{"low", "Extra high", "medium"} {
		if err := Configure(ctx, r, "s", st, ThoughtLevelSetting, want); err != nil {
			t.Fatal(err)
		}
	}
	if strings.Join(r.calls, ",") != "reasoning_effort=low,reasoning_effort=xhigh" {
		t.Fatalf("calls: %v", r.calls)
	}
	if err := Configure(ctx, r, "s", st, ThoughtLevelSetting, "ultra"); err == nil || !strings.Contains(err.Error(), `harness.thought_level "ultra" is not one the agent offers [low medium xhigh]`) {
		t.Fatalf("unknown level: %v", err)
	}
	if err := Configure(ctx, r, "s", SessionState{}, ThoughtLevelSetting, "low"); err == nil || !strings.Contains(err.Error(), "offers no thought_level option") {
		t.Fatalf("no option: %v", err)
	}
	if err := Configure(ctx, r, "s", st, ThoughtLevelSetting, ""); err != nil || len(r.calls) != 2 {
		t.Fatalf("empty: %v %v", err, r.calls)
	}
}

// A session request's _meta: the profile's metadata and the system prompt marker, never shared
// with the profile's map.
func TestSessionMeta(t *testing.T) {
	if SessionMeta(nil, "") != nil {
		t.Fatal("nothing: nil")
	}
	profile := map[string]any{"claudeCode": map[string]any{"options": map[string]any{"maxTurns": 50}}}
	m := SessionMeta(profile, "Be brief.")
	if m[SystemPromptMetaKey] != "Be brief." || m["claudeCode"] == nil {
		t.Fatalf("meta: %v", m)
	}
	if _, leaked := profile[SystemPromptMetaKey]; leaked {
		t.Fatal("the profile's map was changed")
	}
}
