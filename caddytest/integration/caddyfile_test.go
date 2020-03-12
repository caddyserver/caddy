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
  
  localhost:9080 {
    respond /version 200 {
      body "hello from a.caddy.localhost"
    }	
    }
  `, "caddyfile")

	// act and assert
	caddytest.AssertGetResponse(t, "http://localhost:9080/version", 200, "hello from a.caddy.localhost")
}

func TestRedirect(t *testing.T) {

	// arrange
	caddytest.InitServer(t, `
  {
    http_port     9080
    https_port    9443
  }
  
  localhost:9080 {
    
    redir / http://localhost:9080/hello 301
    
    respond /hello 200 {
      body "hello from b"
    }	
    }
  `, "caddyfile")

	// act and assert
	caddytest.AssertRedirect(t, "http://localhost:9080/", "http://localhost:9080/hello", 301)

	// follow redirect
	caddytest.AssertGetResponse(t, "http://localhost:9080/", 200, "hello from b")
}

func TestDuplicateHosts(t *testing.T) {

	// act and assert
	caddytest.AssertLoadError(t,
		`
    localhost:9080 {
    }
  
    localhost:9080 { 
    }
    `,
		"caddyfile",
		"duplicate site address not allowed")
}
