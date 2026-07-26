package httpcaddyfile

import (
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestShorthandRFC9440Expansion(t *testing.T) {
	replacer := NewShorthandReplacer()

	for i, tc := range []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "leaf certificate shorthand",
			input:    "{tls_client_certificate_rfc9440}",
			expected: "{http.request.tls.client.certificate_rfc9440}",
		},
		{
			name:     "chain certificate shorthand",
			input:    "{tls_client_certificate_chain_rfc9440}",
			expected: "{http.request.tls.client.certificate_chain_rfc9440}",
		},
		{
			name:     "both shorthands in a single token",
			input:    "{tls_client_certificate_rfc9440} {tls_client_certificate_chain_rfc9440}",
			expected: "{http.request.tls.client.certificate_rfc9440} {http.request.tls.client.certificate_chain_rfc9440}",
		},
	} {
		seg := caddyfile.Segment{caddyfile.Token{Text: tc.input}}
		replacer.ApplyToSegment(&seg)
		actual := seg[0].Text
		if actual != tc.expected {
			t.Errorf("Test %d (%s): shorthand %q: expected %q, got %q", i, tc.name, tc.input, tc.expected, actual)
		}
	}

	// Verify shorthand expansion through a full Caddyfile adapt cycle
	// using the respond builtin which embeds the expanded placeholder
	// into the adapted JSON body field.
	adapter := caddyfile.Adapter{
		ServerType: ServerType{},
	}

	caddyfileInput := `:8080 {
		respond "{tls_client_certificate_rfc9440} {tls_client_certificate_chain_rfc9440}"
	}
	`

	out, _, err := adapter.Adapt([]byte(caddyfileInput), nil)
	if err != nil {
		t.Fatalf("failed to adapt Caddyfile: %v", err)
	}
	adapted := string(out)

	if !strings.Contains(adapted, "http.request.tls.client.certificate_rfc9440") {
		t.Errorf("adapted JSON missing expanded leaf placeholder; got: %s", adapted)
	}
	if !strings.Contains(adapted, "http.request.tls.client.certificate_chain_rfc9440") {
		t.Errorf("adapted JSON missing expanded chain placeholder; got: %s", adapted)
	}
}
