package harness

import "testing"

func TestParseUsage(t *testing.T) {
	claude := `{"type":"result","subtype":"success","is_error":false,"duration_ms":8123,"num_turns":4,"result":"done","session_id":"s","total_cost_usd":0.0421,"usage":{"input_tokens":12,"cache_creation_input_tokens":1500,"cache_read_input_tokens":22000,"output_tokens":640},"modelUsage":{"claude-opus-5-5":{"inputTokens":12,"outputTokens":640,"costUSD":0.0421}}}`
	u, mode, ok := ParseUsage(claude)
	if !ok || mode != Total {
		t.Fatalf("claude result not recognised: ok=%v mode=%v", ok, mode)
	}
	if u.CostUSD != 0.0421 || u.OutputTokens != 640 || u.CacheRead != 22000 || u.CacheWrite != 1500 || u.Turns != 4 || u.Model != "claude-opus-5-5" {
		t.Fatalf("bad parse: %+v", u)
	}
	u, mode, ok = ParseUsage(`{"type":"usage","model":"gpt-x","input_tokens":100,"output_tokens":50,"cost_usd":0.001}`)
	if !ok || mode != Increment || u.InputTokens != 100 || u.Model != "gpt-x" {
		t.Fatalf("generic usage: ok=%v mode=%v %+v", ok, mode, u)
	}
	for _, l := range []string{"plain text", `{"type":"assistant","message":{}}`, `{"type":"result"}`, "", "{"} {
		if _, _, ok := ParseUsage(l); ok {
			t.Fatalf("%q must not parse as usage", l)
		}
	}
}

func TestParseSession(t *testing.T) {
	cases := map[string]string{
		`{"type":"system","subtype":"init","session_id":"abc-123","model":"x"}`: "abc-123",
		`{"type":"thread.started","thread_id":"th_9"}`:                          "th_9",
		`{"type":"result","session_id":"abc-123","total_cost_usd":0.1}`:         "abc-123",
		`plain text with session_id in it`:                                      "",
		`{"type":"usage","input_tokens":1}`:                                     "",
	}
	for line, want := range cases {
		got, ok := ParseSession(line)
		if got != want || ok != (want != "") {
			t.Errorf("ParseSession(%q) = %q,%v want %q", line, got, ok, want)
		}
	}
}
