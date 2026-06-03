package reverseproxy

import (
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap"
)

func TestSetBodyJSONPlaceholders(t *testing.T) {
	h := Handler{}
	logger := zap.NewNop()

	tests := []struct {
		name     string
		body     string
		expected map[string]string
	}{
		{
			name: "flat booleans",
			body: `{"manage":true,"read":false}`,
			expected: map[string]string{
				"http.reverse_proxy.body.manage": "true",
				"http.reverse_proxy.body.read":   "false",
			},
		},
		{
			name: "flat string and number",
			body: `{"role":"admin","count":42}`,
			expected: map[string]string{
				"http.reverse_proxy.body.role":  "admin",
				"http.reverse_proxy.body.count": "42",
			},
		},
		{
			name: "nested dot notation",
			body: `{"user":{"role":"superuser","active":true}}`,
			expected: map[string]string{
				"http.reverse_proxy.body.user.role":   "superuser",
				"http.reverse_proxy.body.user.active": "true",
			},
		},
		{
			name: "null value",
			body: `{"token":null}`,
			expected: map[string]string{
				"http.reverse_proxy.body.token": "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repl := caddy.NewReplacer()
			h.setBodyJSONPlaceholders(repl, []byte(tt.body), logger)
			for key, want := range tt.expected {
				got, ok := repl.Get(key)
				if !ok {
					t.Errorf("placeholder %q not set", key)
					continue
				}
				if got != want {
					t.Errorf("placeholder %q: got %q, want %q", key, got, want)
				}
			}
		})
	}
}

func TestSetBodyJSONPlaceholders_InvalidJSON(t *testing.T) {
	h := Handler{}
	logger := zap.NewNop()
	repl := caddy.NewReplacer()
	h.setBodyJSONPlaceholders(repl, []byte("not json"), logger)
	if _, ok := repl.Get("http.reverse_proxy.body.anything"); ok {
		t.Error("expected no placeholders set for invalid JSON")
	}
}

func TestParseResponseBodyJSONCaddyfile(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    bool
		wantErr bool
	}{
		{
			name:  "enabled",
			input: "reverse_proxy localhost:9000 {\n\tparse_response_body_json\n}",
			want:  true,
		},
		{
			name:  "not set",
			input: "reverse_proxy localhost:9000 {\n}",
			want:  false,
		},
		{
			name:    "duplicate",
			input:   "reverse_proxy localhost:9000 {\n\tparse_response_body_json\n\tparse_response_body_json\n}",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &Handler{}
			d := caddyfile.NewTestDispenser(tt.input)
			err := h.UnmarshalCaddyfile(d)
			if (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalCaddyfile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && h.ParseResponseBodyJSON != tt.want {
				t.Errorf("ParseResponseBodyJSON = %v, want %v", h.ParseResponseBodyJSON, tt.want)
			}
		})
	}
}
