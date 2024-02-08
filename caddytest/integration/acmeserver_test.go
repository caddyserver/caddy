package integration

import (
	"testing"

	"github.com/caddyserver/caddy/v2/caddytest"
)

func TestACMEServerDirectory(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(`
	{
		skip_install_trust
		local_certs
		admin localhost:2999
		http_port     9080
		https_port    9443
		pki {
			ca local {
				name "Caddy Local Authority"
			}
		}
	}
	acme.localhost:9443 {
		acme_server
	}
  `, "caddyfile")
	tester.AssertGetResponse(
		"https://acme.localhost:9443/acme/local/directory",
		200,
		`{"newNonce":"https://acme.localhost:9443/acme/local/new-nonce","newAccount":"https://acme.localhost:9443/acme/local/new-account","newOrder":"https://acme.localhost:9443/acme/local/new-order","revokeCert":"https://acme.localhost:9443/acme/local/revoke-cert","keyChange":"https://acme.localhost:9443/acme/local/key-change"}
`)
}
