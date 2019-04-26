package caddytls

import (
	"crypto/tls"

	"bitbucket.org/lightcodelabs/caddy2"
)

type (
	// MatchServerName matches based on SNI.
	MatchServerName []string

	// TODO: these others should be enterprise-only, probably

	// MatchProtocol matches based on protocol.
	MatchProtocol []string // TODO: Protocol or version?

	// MatchClientCert matches based on client certificate / client auth?
	MatchClientCert struct{} // TODO: client certificate options

	// MatchRemote matches based on the remote address of the connection.
	MatchRemote []string

	// MatchStarlark matches based on a Starlark script.
	MatchStarlark string
)

func init() {
	caddy2.RegisterModule(caddy2.Module{
		Name: "tls.handshake_match.host",
		New:  func() (interface{}, error) { return MatchServerName{}, nil },
	})
	caddy2.RegisterModule(caddy2.Module{
		Name: "tls.handshake_match.protocol",
		New:  func() (interface{}, error) { return MatchProtocol{}, nil },
	})
	caddy2.RegisterModule(caddy2.Module{
		Name: "tls.handshake_match.client_cert",
		New:  func() (interface{}, error) { return MatchClientCert{}, nil },
	})
	caddy2.RegisterModule(caddy2.Module{
		Name: "tls.handshake_match.remote",
		New:  func() (interface{}, error) { return MatchRemote{}, nil },
	})
	caddy2.RegisterModule(caddy2.Module{
		Name: "tls.handshake_match.starlark",
		New:  func() (interface{}, error) { return new(MatchStarlark), nil },
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

// Match matches hello based on protocol version.
func (m MatchProtocol) Match(hello *tls.ClientHelloInfo) bool {
	// TODO: not implemented
	return false
}

// Match matches hello based on client certificate.
func (m MatchClientCert) Match(hello *tls.ClientHelloInfo) bool {
	// TODO: not implemented
	return false
}

// Match matches hello based on remote address.
func (m MatchRemote) Match(hello *tls.ClientHelloInfo) bool {
	// TODO: not implemented
	return false
}

// Match matches hello based on a Starlark script.
func (m MatchStarlark) Match(hello *tls.ClientHelloInfo) bool {
	// TODO: not implemented
	return false
}

// Interface guards
var (
	_ ConnectionMatcher = MatchServerName{}
	_ ConnectionMatcher = MatchProtocol{}
	_ ConnectionMatcher = MatchClientCert{}
	_ ConnectionMatcher = MatchRemote{}
	_ ConnectionMatcher = new(MatchStarlark)
)
