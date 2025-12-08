package caddytest

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestReplaceCertificatePaths(t *testing.T) {
	rawConfig := `a.caddy.localhost:9443{
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

func TestLoadUnorderedJSON(t *testing.T) {
	harness := StartHarness(t)
	harness.LoadConfig(`
	{
		"logging": {
			"logs": {
				"default": {
					"level": "DEBUG",
					"writer": {
						"output": "stdout"
					}
				},
				"sStdOutLogs": {
					"level": "DEBUG",
					"writer": {
						"output": "stdout"
					},
					"include": [
						"http.*",
						"admin.*"
					]
				},
				"sFileLogs": {
					"level": "DEBUG",
					"writer": {
						"output": "stdout"
					},
					"include": [
						"http.*",
						"admin.*"
					]
				}
			}
		},
		"admin": {
			"listen": "{$TESTING_CADDY_ADMIN_BIND}"
		},
		"apps": {
			"pki": {
				"certificate_authorities" : {
				  "local" : {
					"install_trust": false
				  }
				}
			},
			"http": {
				"http_port": {$TESTING_CADDY_PORT_ONE},
				"https_port": {$TESTING_CADDY_PORT_TWO},
				"servers": {
					"s_server": {
						"listen": [
							":{$TESTING_CADDY_PORT_ONE}",
							":{$TESTING_CADDY_PORT_TWO}"
						],
						"routes": [
							{
								"handle": [
									{
										"handler": "static_response",
										"body": "Hello"
									}
								]
							},
							{
								"match": [
									{
										"host": [
											"localhost",
											"127.0.0.1"
										]
									}
								]
							}
						],
						"logs": {
							"default_logger_name": "sStdOutLogs",
							"logger_names": {
								"localhost": "sStdOutLogs",
								"127.0.0.1": "sFileLogs"
							}
						}
					}
				}
			}
		}
	}
  `, "json")
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://localhost:%d/", harness.Tester().PortOne()), nil)
	if err != nil {
		t.Fail()
		return
	}
	harness.AssertResponseCode(req, 200)
}
