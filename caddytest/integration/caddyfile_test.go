package integration

import (
	"testing"

	"github.com/caddyserver/caddy/v2/caddytest"
)

func TestRespond(t *testing.T) {

	// arrange
	caddytest.InitServer(t, ` 
	{
		http_port     9080
		https_port    9443
	}
	
	a.caddy.local:9443 {
		tls /caddy.local.crt /caddy.local.key {
		}
		respond /version 200 {
		  body "hello from a.caddy.local"
		}	
	  }
	`, "caddyfile")

	// act and assert
	caddytest.AssertGetResponse(t, "https://a.caddy.local:9443/version", 200, "hello from a.caddy.local")
}

func TestRedirect(t *testing.T) {

	// arrange
	caddytest.InitServer(t, `
	{
		http_port     9080
		https_port    9443
	}
	
	b.caddy.local:9443 {
		tls /caddy.local.crt /caddy.local.key {
		}

		redir / https://b.caddy.local:9443/hello 301
		
		respond /hello 200 {
		  body "hello from b.caddy.local"
		}	
	  }
	`, "caddyfile")

	// act and assert
	caddytest.AssertRedirect(t, "https://b.caddy.local:9443/", "https://b.caddy.local:9443/hello", 301)

	// follow redirect
	caddytest.AssertGetResponse(t, "https://b.caddy.local:9443/", 200, "hello from b.caddy.local")
}
