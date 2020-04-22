package caddytest

import (
	"bytes"
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

func TestAssertPostResponse(t *testing.T) {
	rawConfig := `{
	  "logging": {
		"logs": {
		  "default": {
			"level": "DEBUG"
		  }
		}
	  },
	  "apps": {
		"http": {
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
					  "body": "OK",
					  "handler": "static_response",
					  "status_code": 200
					}
				  ],
				  "match": [
					{
					  "path": [
						"/health"
					  ]
					}
				  ],
				  "terminal": true
				}
			  ],
			  "tls_connection_policies": [
				{
				  "certificate_selection": {
					"any_tag": [
					  "cert0"
					]
				  }
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
		},
		"pki": {
		  "certificate_authorities": {
			"local": {
			  "install_trust": false
			}
		  }
		}
	  }
	}`
	baseURL := "https://localhost:9443"
	InitServer(t, rawConfig, "json")
	AssertGetResponse(t, baseURL+"/health", 200, "OK")
	reqHeaders := []string{
		"Content-Type: application/x-www-form-urlencoded",
	}
	reqPayload := bytes.NewBufferString("foo=bar")
	AssertPostResponse(t, baseURL+"/health", reqHeaders, reqPayload, 200, "OK")
}
