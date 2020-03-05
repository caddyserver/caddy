package integration

import (
	"testing"

	"github.com/caddyserver/caddy/v2/caddytest"
)

func TestHttpOnly(t *testing.T) {

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

func TestRespondNoMatchingDNS(t *testing.T) {

	//NB: this fails because the a.caddy.local is not found via DNS, routing via the custom dialer happens after dns resolution

	// arrange
	caddytest.InitServer(t, ` 
  {
    http_port     9080
    https_port    9443
    default_sni   *.caddy.localhost
  }
  
  a.caddy.local:9443 {
    tls /caddy.localhost.crt /caddy.localhost.key {
    }
    respond /version 200 {
      body "hello from a.caddy.localhost"
    }	
  }
  `, "caddyfile")

	// act and assert
	caddytest.AssertGetResponse(t, "https://a.caddy.local:9443/version", 200, "hello from a.caddy.localhost")
}

func TestRespondValidButRemoteDNS(t *testing.T) {

	// this works and gets routed via the custom dialer. If I crafted a self signed cert of cnn.com this would work over https

	// arrange
	caddytest.InitServer(t, ` 
  {
    http_port     9080
    https_port    9443
    default_sni   *.caddy.localhost
  }
  
  www.cnn.com:9080 {
    

    respond /version 200 {
      body "hello from a.caddy.localhost"
    }	
  }
  `, "caddyfile")

	// act and assert
	caddytest.AssertGetResponse(t, "http://www.cnn.com:9080/version", 200, "hello from a.caddy.localhost")
}

func TestDefaultSNI(t *testing.T) {

	// arrange
	caddytest.InitServer(t, ` 
  {
    http_port     9080
    https_port    9443
    default_sni   *.caddy.localhost
  }
  
  127.0.0.1:9443 {
    tls /caddy.localhost.crt /caddy.localhost.key {
    }
    respond /version 200 {
      body "hello from a.caddy.localhost"
    }	
  }
  `, "caddyfile")

	// act and assert
	caddytest.AssertGetResponse(t, "https://127.0.0.1:9443/version", 200, "hello from a.caddy.localhost")
}

func TestRedirect(t *testing.T) {

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

func Test2Hosts(t *testing.T) {

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

func Test2HostsAndOneStaticIP(t *testing.T) {

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
