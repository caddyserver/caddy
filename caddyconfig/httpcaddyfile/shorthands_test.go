package httpcaddyfile

import (
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestShorthandReplacerSimpleReplacements(t *testing.T) {
	sr := NewShorthandReplacer()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "host",
			input: "{host}",
			want:  "{http.request.host}",
		},
		{
			name:  "hostport",
			input: "{hostport}",
			want:  "{http.request.hostport}",
		},
		{
			name:  "port",
			input: "{port}",
			want:  "{http.request.port}",
		},
		{
			name:  "method",
			input: "{method}",
			want:  "{http.request.method}",
		},
		{
			name:  "uri",
			input: "{uri}",
			want:  "{http.request.uri}",
		},
		{
			name:  "path",
			input: "{path}",
			want:  "{http.request.uri.path}",
		},
		{
			name:  "query",
			input: "{query}",
			want:  "{http.request.uri.query}",
		},
		{
			name:  "scheme",
			input: "{scheme}",
			want:  "{http.request.scheme}",
		},
		{
			name:  "remote_host",
			input: "{remote_host}",
			want:  "{http.request.remote.host}",
		},
		{
			name:  "remote_port",
			input: "{remote_port}",
			want:  "{http.request.remote.port}",
		},
		{
			name:  "uuid",
			input: "{uuid}",
			want:  "{http.request.uuid}",
		},
		{
			name:  "tls_cipher",
			input: "{tls_cipher}",
			want:  "{http.request.tls.cipher_suite}",
		},
		{
			name:  "tls_version",
			input: "{tls_version}",
			want:  "{http.request.tls.version}",
		},
		{
			name:  "client_ip",
			input: "{client_ip}",
			want:  "{http.vars.client_ip}",
		},
		{
			name:  "upstream_hostport",
			input: "{upstream_hostport}",
			want:  "{http.reverse_proxy.upstream.hostport}",
		},
		{
			name:  "dir",
			input: "{dir}",
			want:  "{http.request.uri.path.dir}",
		},
		{
			name:  "file",
			input: "{file}",
			want:  "{http.request.uri.path.file}",
		},
		{
			name:  "orig_method",
			input: "{orig_method}",
			want:  "{http.request.orig_method}",
		},
		{
			name:  "orig_uri",
			input: "{orig_uri}",
			want:  "{http.request.orig_uri}",
		},
		{
			name:  "orig_path",
			input: "{orig_path}",
			want:  "{http.request.orig_uri.path}",
		},
		{
			name:  "no matching placeholder",
			input: "{unknown}",
			want:  "{unknown}",
		},
		{
			name:  "not a placeholder",
			input: "plain text",
			want:  "plain text",
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
		{
			name:  "multiple placeholders in one string",
			input: "{host}:{port}",
			want:  "{http.request.host}:{http.request.port}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			segment := caddyfile.Segment{{Text: tt.input}}
			sr.ApplyToSegment(&segment)
			got := segment[0].Text
			if got != tt.want {
				t.Errorf("ApplyToSegment(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestShorthandReplacerComplexReplacements(t *testing.T) {
	sr := NewShorthandReplacer()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "header placeholder",
			input: "{header.X-Forwarded-For}",
			want:  "{http.request.header.X-Forwarded-For}",
		},
		{
			name:  "cookie placeholder",
			input: "{cookie.session_id}",
			want:  "{http.request.cookie.session_id}",
		},
		{
			name:  "labels placeholder",
			input: "{labels.0}",
			want:  "{http.request.host.labels.0}",
		},
		{
			name:  "path segment placeholder",
			input: "{path.0}",
			want:  "{http.request.uri.path.0}",
		},
		{
			name:  "query placeholder",
			input: "{query.page}",
			want:  "{http.request.uri.query.page}",
		},
		{
			name:  "re placeholder with dots",
			input: "{re.name.group}",
			want:  "{http.regexp.name.group}",
		},
		{
			name:  "vars placeholder",
			input: "{vars.my_var}",
			want:  "{http.vars.my_var}",
		},
		{
			name:  "rp placeholder",
			input: "{rp.upstream.address}",
			want:  "{http.reverse_proxy.upstream.address}",
		},
		{
			name:  "resp placeholder",
			input: "{resp.status_code}",
			want:  "{http.intercept.status_code}",
		},
		{
			name:  "err placeholder",
			input: "{err.status_code}",
			want:  "{http.error.status_code}",
		},
		{
			name:  "file_match placeholder",
			input: "{file_match.relative}",
			want:  "{http.matchers.file.relative}",
		},
		{
			name:  "header with hyphen",
			input: "{header.Content-Type}",
			want:  "{http.request.header.Content-Type}",
		},
		{
			name:  "header with underscore",
			input: "{header.X_Custom_Header}",
			want:  "{http.request.header.X_Custom_Header}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			segment := caddyfile.Segment{{Text: tt.input}}
			sr.ApplyToSegment(&segment)
			got := segment[0].Text
			if got != tt.want {
				t.Errorf("ApplyToSegment(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestShorthandReplacerApplyToNilSegment(t *testing.T) {
	sr := NewShorthandReplacer()
	// Should not panic
	sr.ApplyToSegment(nil)
}

func TestShorthandReplacerMultipleTokens(t *testing.T) {
	sr := NewShorthandReplacer()

	segment := caddyfile.Segment{
		{Text: "{host}"},
		{Text: "{path}"},
		{Text: "{header.X-Test}"},
		{Text: "plain"},
	}

	sr.ApplyToSegment(&segment)

	expected := []string{
		"{http.request.host}",
		"{http.request.uri.path}",
		"{http.request.header.X-Test}",
		"plain",
	}

	for i, want := range expected {
		if segment[i].Text != want {
			t.Errorf("token %d: got %q, want %q", i, segment[i].Text, want)
		}
	}
}

func TestShorthandReplacerEmptySegment(t *testing.T) {
	sr := NewShorthandReplacer()
	segment := caddyfile.Segment{}
	sr.ApplyToSegment(&segment) // should not panic
}

func TestShorthandReplacerEscapedPlaceholders(t *testing.T) {
	sr := NewShorthandReplacer()

	// Percent-escaped path placeholder
	segment := caddyfile.Segment{{Text: "{%path}"}}
	sr.ApplyToSegment(&segment)
	if segment[0].Text != "{http.request.uri.path_escaped}" {
		t.Errorf("got %q, want {http.request.uri.path_escaped}", segment[0].Text)
	}

	// Percent-escaped query placeholder
	segment = caddyfile.Segment{{Text: "{%query}"}}
	sr.ApplyToSegment(&segment)
	if segment[0].Text != "{http.request.uri.query_escaped}" {
		t.Errorf("got %q, want {http.request.uri.query_escaped}", segment[0].Text)
	}

	// Prefixed query
	segment = caddyfile.Segment{{Text: "{?query}"}}
	sr.ApplyToSegment(&segment)
	if segment[0].Text != "{http.request.uri.prefixed_query}" {
		t.Errorf("got %q, want {http.request.uri.prefixed_query}", segment[0].Text)
	}
}
