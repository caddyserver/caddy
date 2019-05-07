package caddytls

import (
	"crypto/tls"

	"bitbucket.org/lightcodelabs/caddy2"
)

// MatchServerName matches based on SNI.
type MatchServerName []string

func init() {
	caddy2.RegisterModule(caddy2.Module{
		Name: "tls.handshake_match.host",
		New:  func() (interface{}, error) { return MatchServerName{}, nil },
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
var _ ConnectionMatcher = MatchServerName{}
