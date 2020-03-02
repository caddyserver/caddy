package integration

import (
	"testing"

	"github.com/caddyserver/caddy/v2/caddytest"
)

func xTestHttpOnly(t *testing.T) {

	// arrange
	caddytest.InitServer(t, ` 
  {
    http_port     9080
    https_port    9443
  }
  
  a.caddy.localhost:9080 {
    respond /version 200 {
      body "hello from a.caddy.localhost"
    }	
    }
  `, "caddyfile")

	// act and assert
	caddytest.AssertGetResponse(t, "http://a.caddy.localhost:9080/version", 200, "hello from a.caddy.localhost")
}

func TestRespond(t *testing.T) {

	// arrange
	caddytest.InitServer(t, ` 
  {
    http_port     9080
    https_port    9443
  }
  
  a.caddy.localhost:9443 {
    tls /caddy.localhost.crt /caddy.localhost.key {
    }
    respond /version 200 {
      body "hello from a.caddy.localhost"
    }	
  }
  `, "caddyfile")

	// act and assert
	caddytest.AssertGetResponse(t, "https://a.caddy.localhost:9443/version", 200, "hello from a.caddy.localhost")
}

func xTestRedirect(t *testing.T) {

	// arrange
	caddytest.InitServer(t, `
  {
    http_port     9080
    https_port    9443
  }
  
  b.caddy.localhost:9443 {
    tls /caddy.localhost.crt /caddy.localhost.key {
    }

    redir / https://b.caddy.localhost:9443/hello 301
    
    respond /hello 200 {
      body "hello from b.caddy.localhost"
    }	
    }
  `, "caddyfile")

	// act and assert
	caddytest.AssertRedirect(t, "https://b.caddy.localhost:9443/", "https://b.caddy.localhost:9443/hello", 301)

	// follow redirect
	caddytest.AssertGetResponse(t, "https://b.caddy.localhost:9443/", 200, "hello from b.caddy.localhost")
}

func xTest2Hosts(t *testing.T) {

	// arrange
	caddytest.InitServer(t, `
  {
    http_port     9080
    https_port    9443
  }
  
  a.caddy.localhost:9443 {
    tls /caddy.localhost.crt /caddy.localhost.key {
    }

    respond /hello 200 {
      body "hello from a.caddy.localhost"
    }	
  }

  b.caddy.localhost:9443 {
    tls /caddy.localhost.crt /caddy.localhost.key {
    }

    respond /hello 200 {
      body "hello from b.caddy.localhost"
    }	
    }
  `, "caddyfile")

	// act and assert
	caddytest.AssertGetResponse(t, "https://a.caddy.localhost:9443/hello", 200, "hello from a.caddy.localhost")
	caddytest.AssertGetResponse(t, "https://b.caddy.localhost:9443/hello", 200, "hello from b.caddy.localhost")
}

func xTest2HostsAndOneStaticIP(t *testing.T) {

	// arrange
	caddytest.InitServer(t, `
  {
    http_port     9080
    https_port    9443
  }
  
  a.caddy.localhost:9443, 127.0.0.1:9080 {
    tls /caddy.localhost.crt /caddy.localhost.key {
    }

    respond /hello 200 {
      body "hello from a.caddy.localhost"
    }	
  }

  b.caddy.localhost:9443 {
    tls /caddy.localhost.crt /caddy.localhost.key {
    }

    respond /hello 200 {
      body "hello from b.caddy.localhost"
    }	
    }
  `, "caddyfile")

	// act and assert
	caddytest.AssertGetResponse(t, "http://127.0.0.1:9080/hello", 200, "hello from a.caddy.localhost")
	caddytest.AssertGetResponse(t, "https://a.caddy.localhost:9443/hello", 200, "hello from a.caddy.localhost")
	caddytest.AssertGetResponse(t, "https://b.caddy.localhost:9443/hello", 200, "hello from b.caddy.localhost")
}
