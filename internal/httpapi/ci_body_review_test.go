package httpapi

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// The public CI exchange accepts exactly one object. These are parser fixtures,
// not real job tokens; invalid bodies must be rejected before an exchange starts.
func TestReviewCIAuthBodyIsExactlyOneObject(t *testing.T) {
	for _, tc := range []struct {
		name  string
		body  string
		valid bool
	}{
		{"object", `{"token":"fixture"}`, true},
		{"whitespace", "{\"token\":\"fixture\"}\n\t ", true},
		{"second_object", `{"token":"fixture"} {}`, false},
		{"closing_brace", `{"token":"fixture"}}`, false},
		{"closing_bracket", `{"token":"fixture"}]`, false},
		{"null", `null`, false},
		{"array", `[]`, false},
		{"unknown_field", `{"token":"fixture","extra":true}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var body struct {
				Token string `json:"token"`
			}
			req := httptest.NewRequest("POST", "/v1/auth/ci", strings.NewReader(tc.body))
			err := decodeStrict(httptest.NewRecorder(), req, &body, 32*1024)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v, decoder error=%v", tc.valid, err)
			}
		})
	}
}
