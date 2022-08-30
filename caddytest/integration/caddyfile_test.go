package integration

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/caddyserver/caddy/v2/caddytest"
)

func TestRespond(t *testing.T) {

	// arrange
	tester := caddytest.NewTester(t)
	tester.InitServer(` 
  {
    http_port     9080
    https_port    9443
  }
  
  localhost:9080 {
    respond /version 200 {
      body "hello from localhost"
    }	
    }
  `, "caddyfile")

	// act and assert
	tester.AssertGetResponse("http://localhost:9080/version", 200, "hello from localhost")
}

func TestRedirect(t *testing.T) {

	// arrange
	tester := caddytest.NewTester(t)
	tester.InitServer(`
  {
    http_port     9080
    https_port    9443
  }
  
  localhost:9080 {
    
    redir / http://localhost:9080/hello 301
    
    respond /hello 200 {
      body "hello from localhost"
    }	
    }
  `, "caddyfile")

	// act and assert
	tester.AssertRedirect("http://localhost:9080/", "http://localhost:9080/hello", 301)

	// follow redirect
	tester.AssertGetResponse("http://localhost:9080/", 200, "hello from localhost")
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
		"ambiguous site definition")
}

func TestReadCookie(t *testing.T) {

	localhost, _ := url.Parse("http://localhost")
	cookie := http.Cookie{
		Name:  "clientname",
		Value: "caddytest",
	}

	// arrange
	tester := caddytest.NewTester(t)
	tester.Client.Jar.SetCookies(localhost, []*http.Cookie{&cookie})
	tester.InitServer(` 
  {
    http_port     9080
    https_port    9443
  }
  
  localhost:9080 {
    templates {
      root testdata
    }
    file_server {
      root testdata
    }
  }
  `, "caddyfile")

	// act and assert
	tester.AssertGetResponse("http://localhost:9080/cookie.html", 200, "<h2>Cookie.ClientName caddytest</h2>")
}

func TestReplIndex(t *testing.T) {

	tester := caddytest.NewTester(t)
	tester.InitServer(`
  {
    http_port     9080
    https_port    9443
  }

  localhost:9080 {
    templates {
      root testdata
    }
    file_server {
      root testdata
      index "index.{host}.html"
    }
  }
  `, "caddyfile")

	// act and assert
	tester.AssertGetResponse("http://localhost:9080/", 200, "")
}
