package httpcaddyfile

import (
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestShorthandDefaults(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{`{path:-/index.html}`, `{http.request.uri.path:-/index.html}`},
		{`{header.X-User:-{cookie.user:-{query.user:-anonymous}}}`, `{http.request.header.X-User:-{http.request.cookie.user:-{http.request.uri.query.user:-anonymous}}}`},
		{`{vars.name:-{re.route.1:-{host}}}`, `{http.vars.name:-{http.regexp.route.1:-{http.request.host}}}`},
		{`{path:-a:b}`, `{http.request.uri.path:-a:b}`},
		{`{"message":"literal:-value"}`, `{"message":"literal:-value"}`},
		{`{http.request.header.X-User:-header.X-User}`, `{http.request.header.X-User:-header.X-User}`},
		{`{prefixheader.X-User:-{query.user}}`, `{prefixheader.X-User:-{http.request.uri.query.user}}`},
		{`{query.user.suffix:-{vars.name}}`, `{query.user.suffix:-{http.vars.name}}`},
		{`{hostsuffix:-host}`, `{hostsuffix:-host}`},
		{`{missing:-header.X-User query.user host}`, `{missing:-header.X-User query.user host}`},
		{`{missing:-\{host\}}`, `{missing:-\{host\}}`},
		{`\{host}`, `\{http.request.host}`},
		{`{"message":"{host}","fallback":"{query.user:-anonymous}"}`, `{"message":"{http.request.host}","fallback":"{http.request.uri.query.user:-anonymous}"}`},
	} {
		segment := caddyfile.Segment{{Text: tc.input}}
		NewShorthandReplacer().ApplyToSegment(&segment)
		if got := segment[0].Text; got != tc.want {
			t.Errorf("%s: got %s, want %s", tc.input, got, tc.want)
		}
	}
}
