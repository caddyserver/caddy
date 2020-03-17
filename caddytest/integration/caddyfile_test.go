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
      body "hello from localhost"
    }	
    }
  `, "caddyfile")

	// act and assert
	caddytest.AssertGetResponse(t, "http://localhost:9080/version", 200, "hello from localhost")
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
      body "hello from localhost"
    }	
    }
  `, "caddyfile")

	// act and assert
	caddytest.AssertRedirect(t, "http://localhost:9080/", "http://localhost:9080/hello", 301)

	// follow redirect
	caddytest.AssertGetResponse(t, "http://localhost:9080/", 200, "hello from localhost")
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

func xTestDefaultSNI(t *testing.T) {

	// arrange
	caddytest.InitServer(t, ` 
  {
    http_port     9080
    https_port    9443
    default_sni   *.caddy.localhost
  }
  
  127.0.0.1:9443 {
    tls /caddy.localhost.crt /caddy.localhost.key
    respond /version 200 {
      body "hello from a"
    }	
  }
  `, "caddyfile")

	// act and assert
	caddytest.AssertGetResponse(t, "https://127.0.0.1:9443/version", 200, "hello from a")
}

func TestDefaultSNIWithNamedHostAndExplicitIP(t *testing.T) {

	// arrange
	caddytest.InitServer(t, ` 
  {
    http_port     9080
    https_port    9443
    default_sni   a.caddy.localhost
  }
  
  a.caddy.localhost:9443, 127.0.0.1:9443 {
    tls /a.caddy.localhost.crt /a.caddy.localhost.key
    respond /version 200 {
      body "hello from a"
    }	
  }
  `, "caddyfile")

	// act and assert
	// makes a request with no sni
	caddytest.AssertGetResponse(t, "https://127.0.0.1:9443/version", 200, "hello from a")
}

func TestDefaultSNIWithPortMappingOnly(t *testing.T) {

	// arrange
	caddytest.InitServer(t, ` 
  {
    http_port     9080
    https_port    9443
    default_sni   a.caddy.localhost
  }
  
  :9443 {
    tls /a.caddy.localhost.crt /a.caddy.localhost.key
    respond /version 200 {
      body "hello from a.caddy.localhost"
    }	
  }
  `, "caddyfile")

	// act and assert
	// makes a request with no sni
	caddytest.AssertGetResponse(t, "https://127.0.0.1:9443/version", 200, "hello from a")
}

func TestDefaultSNIWithJson(t *testing.T) {

	// arrange
	caddytest.InitServer(t, `{
    "apps": {
      "http": {
        "http_port": 9080,
        "https_port": 9443,
        "servers": {
          "srv0": {
            "listen": [
              ":9443"
            ],
            "routes": [
              {
                "handle": [
                  {
                    "handler": "subroute",
                    "routes": [
                      {
                        "handle": [
                          {
                            "body": "hello from a.caddy.localhost",
                            "handler": "static_response",
                            "status_code": 200
                          }
                        ],
                        "match": [
                          {
                            "path": [
                              "/version"
                            ]
                          }
                        ]
                      }
                    ]
                  }
                ],
                "match": [
                  {
                    "host": [
                      "127.0.0.1"
                    ]
                  }
                ],
                "terminal": true
              }
            ],
            "tls_connection_policies": [
              {
                "certificate_selection": {
                  "policy": "custom",
                  "tag": "cert0"
                },
                "match": {
                  "sni": [
                    "127.0.0.1"
                  ]
                }
              },
              {
                "default_sni": "*.caddy.localhost"
              }
            ]
          }
        }
      },
      "tls": {
        "certificates": {
          "load_files": [
            {
              "certificate": "/caddy.localhost.crt",
              "key": "/caddy.localhost.key",
              "tags": [
                "cert0"
              ]
            }
          ]
        }
      }
    }
  }
  `, "json")

	// act and assert
	// makes a request with no sni
	caddytest.AssertGetResponse(t, "https://127.0.0.1:9443/version", 200, "hello from a")
}
