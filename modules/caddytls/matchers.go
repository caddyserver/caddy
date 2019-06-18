package caddytls

import (
	"crypto/tls"

	"github.com/caddyserver/caddy"
)

// MatchServerName matches based on SNI.
type MatchServerName []string

func init() {
	caddy.RegisterModule(caddy.Module{
		Name: "tls.handshake_match.sni",
		New:  func() interface{} { return MatchServerName{} },
	})
}

// Match matches hello based on SNI.
func (m MatchServerName) Match(hello *tls.ClientHelloInfo) bool {
	for _, name := range m {
		// TODO: support wildcards (and regex?)
		if hello.ServerName == name {
			return true
		}
	}
	return false
}

// Interface guard
var _ ConnectionMatcher = (*MatchServerName)(nil)
