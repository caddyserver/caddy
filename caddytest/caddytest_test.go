package caddytest

import (
	"strings"
	"testing"
)

func TestReplaceCertificatePaths(t *testing.T) {
	rawConfig := `a.caddy.localhost:9443 {
		tls /caddy.localhost.crt /caddy.localhost.key {
		}

		redir / https://b.caddy.localhost:9443/version 301
    
		respond /version 200 {
		  body "hello from a.caddy.localhost"
		}	
	  }`

	r := prependCaddyFilePath(rawConfig)

	if !strings.Contains(r, getIntegrationDir()+"/caddy.localhost.crt") {
		t.Error("expected the /caddy.localhost.crt to be expanded to include the full path")
	}

	if !strings.Contains(r, getIntegrationDir()+"/caddy.localhost.key") {
		t.Error("expected the /caddy.localhost.crt to be expanded to include the full path")
	}

	if !strings.Contains(r, "https://b.caddy.localhost:9443/version") {
		t.Error("expected redirect uri to be unchanged")
	}
}
