package mcpproxy

import (
	"testing"

	"agent-sandbox/internal/policy"
)

func TestCheck(t *testing.T) {
	ro := &policy.MCPRule{ReadOnly: true, Tools: []string{"get_*", "search"}}
	cases := []struct {
		rule *policy.MCPRule
		body string
		deny bool
	}{
		{ro, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, false},
		{ro, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_user","arguments":{}}}`, false},
		{ro, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search"}}`, false},
		{ro, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_user"}}`, true},
		{ro, `[{"jsonrpc":"2.0","id":1,"method":"tools/list"},{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"drop_table"}}]`, true},
		{ro, `{"jsonrpc":"2.0","id":1,"method":"resources/write"}`, true},
		{ro, `{"jsonrpc":"2.0","id":1,"result":{}}`, false},
		{ro, `not json`, true},
		{&policy.MCPRule{ReadOnly: true}, `{"method":"tools/call","params":{"name":"get_user"}}`, true},
		{&policy.MCPRule{}, `{"method":"tools/call","params":{"name":"drop_table"}}`, false},
		{nil, `{"method":"tools/call","params":{"name":"drop_table"}}`, false},
	}
	for _, c := range cases {
		if got := check(c.rule, []byte(c.body)) != ""; got != c.deny {
			t.Errorf("check(%v, %s): deny=%v, want %v", c.rule, c.body, got, c.deny)
		}
	}
}

func TestStrictJSONRPC(t *testing.T) {
	ro := &policy.MCPRule{ReadOnly: true, Tools: []string{"get_*"}}
	for _, body := range []string{
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","Method":"ping","params":{"name":"delete_item"}}`,
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"delete_item","Name":"get_item"}}`,
		`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"delete_item"},"Params":{"name":"get_item"}}`,
		`{"jsonrpc":"2.0","id":7,"Method":"tools/call","params":{"name":"delete_item"}}`,
		`{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"NAME":"delete_item"}}`,
		`{"jsonrpc":"2.0","id":9,"method":"tools/list","method":"tools/call","params":{"name":"delete_item"}}`,
		`{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"get_item"}} {"method":"tools/call","params":{"name":"delete_item"}}`,
		`{"jsonrpc":"2.0","id":11,"method":"tools/call","params":["delete_item"]}`,
		`{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{}}`,
		`"tools/list"`,
		`[1,2]`,
	} {
		if check(ro, []byte(body)) == "" {
			t.Errorf("ambiguous or malformed body must be refused: %s", body)
		}
	}
	for _, body := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_item","arguments":{"Method":"x","name":"ignored"}}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"cursor":"abc"}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`[{"jsonrpc":"2.0","id":3,"method":"ping"},{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"get_x"}}]`,
		`{"jsonrpc":"2.0","id":5,"result":{"Method":"irrelevant"}}`,
	} {
		if r := check(ro, []byte(body)); r != "" {
			t.Errorf("well-formed body must pass: %s: %s", body, r)
		}
	}
}
