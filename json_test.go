package traefik_mtls_authz

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestPolicyJSONUnicode(t *testing.T) {
	base, err := json.Marshal((*validConfig())["policy"])
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, literal, app, wantError string
	}{
		{"invalid-utf8", "\"test\xff\"", "", "valid UTF-8"},
		{"lone-high-surrogate", `"\uD800"`, "", "unpaired Unicode surrogate"},
		{"lone-low-surrogate", `"\udfff"`, "", "unpaired Unicode surrogate"},
		{"high-before-nonsurrogate", `"\uD83D\u0061"`, "", "unpaired Unicode surrogate"},
		{"high-before-escaped-backslash", `"\uD83D\\uDE00"`, "", "unpaired Unicode surrogate"},
		{"surrogate-pair", `"\uD83d\ude00"`, "\U0001f600", ""},
		{"escaped-backslash", `"\\uD800"`, `\uD800`, ""},
		{"replacement-character", "\"\ufffd\"", "\ufffd", ""},
		{"escaped-replacement-character", `"\uFFFD"`, "\ufffd", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := strings.Replace(string(base), `"app":"test"`, `"app":`+tc.literal, 1)
			cfg := map[string]interface{}{"policyJSON": doc}
			h, err := New(context.Background(), http.NotFoundHandler(), &cfg, "test")
			if tc.wantError != "" {
				if h != nil || err == nil || !strings.Contains(err.Error(), tc.wantError) {
					t.Fatalf("New returned handler=%t error=%v, want %q error", h != nil, err, tc.wantError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := h.(*Middleware).policy.App; got != tc.app {
				t.Fatalf("decoded app = %q, want %q", got, tc.app)
			}
		})
	}
}
