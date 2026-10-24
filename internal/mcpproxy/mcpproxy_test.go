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
