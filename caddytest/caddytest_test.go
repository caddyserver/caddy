package caddytest

import (
	"bytes"
	"net/http"
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

func TestLoadUnorderedJSON(t *testing.T) {
	tester := NewTester(t)
	tester.InitServer(`
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
			"listen": "localhost:2999"
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
				"http_port": 9080,
				"https_port": 9443,
				"servers": {
					"s_server": {
						"listen": [
							":9080"
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
	req, err := http.NewRequest(http.MethodGet, "http://localhost:9080/", nil)
	if err != nil {
		t.Fail()
		return
	}
	tester.AssertResponseCode(req, 200)
}

func TestCheckID(t *testing.T) {
	tester := NewTester(t)
	tester.InitServer(`{
		"admin": {
			"listen": "localhost:2999"
		},
		"apps": {
			"http": {
				"http_port": 9080,
				"servers": {
					"s_server": {
						"@id": "s_server",
						"listen": [
							":9080"
						],
						"routes": [
							{
								"handle": [
									{
										"handler": "static_response",
										"body": "Hello"
									}
								]
							}
						]
					}
				}
			}
		}
	}
	`, "json")
	headers := []string{"Content-Type:application/json"}
	sServer1 := []byte(`{"@id":"s_server","listen":[":9080"],"routes":[{"@id":"route1","handle":[{"handler":"static_response","body":"Hello 2"}]}]}`)

	// PUT to an existing ID should fail with a 409 conflict
	tester.AssertPutResponseBody(
		"http://localhost:2999/id/s_server",
		headers,
		bytes.NewBuffer(sServer1),
		409,
		`{"error":"[/config/apps/http/servers/s_server] key already exists: s_server"}`+"\n")

	// POST replaces the object fully
	tester.AssertPostResponseBody(
		"http://localhost:2999/id/s_server",
		headers,
		bytes.NewBuffer(sServer1),
		200,
		"")

	// Verify the server is running the new route
	tester.AssertGetResponse(
		"http://localhost:9080/",
		200,
		"Hello 2")

	// Update the existing route to ensure IDs are handled correctly when replaced
	tester.AssertPostResponseBody(
		"http://localhost:2999/id/s_server",
		headers,
		bytes.NewBuffer([]byte(`{"@id":"s_server","listen":[":9080"],"routes":[{"@id":"route1","handle":[{"handler":"static_response","body":"Hello2"}],"match":[{"path":["/route_1/*"]}]}]}`)),
		200,
		"")

	sServer2 := []byte(`{"@id":"s_server","listen":[":9080"],"routes":[{"@id":"route1","handle":[{"handler":"static_response","body":"Hello2"}],"match":[{"path":["/route_1/*"]}]}]}`)

	// Identical patch should succeed and return 200 (config is unchanged branch)
	tester.AssertPatchResponseBody(
		"http://localhost:2999/id/s_server",
		headers,
		bytes.NewBuffer(sServer2),
		200,
		"")

	route2 := []byte(`{"@id":"route2","handle": [{"handler": "static_response","body": "route2"}],"match":[{"path":["/route_2/*"]}]}`)

	// Put a new route2 object before the route1 object due to the path of /id/route1
	// Being translated to: /config/apps/http/servers/s_server/routes/0
	tester.AssertPutResponseBody(
		"http://localhost:2999/id/route1",
		headers,
		bytes.NewBuffer(route2),
		200,
		"")

	// Verify that the whole config looks correct, now containing both route1 and route2
	tester.AssertGetResponse(
		"http://localhost:2999/config/",
		200,
		`{"admin":{"listen":"localhost:2999"},"apps":{"http":{"http_port":9080,"servers":{"s_server":{"@id":"s_server","listen":[":9080"],"routes":[{"@id":"route2","handle":[{"body":"route2","handler":"static_response"}],"match":[{"path":["/route_2/*"]}]},{"@id":"route1","handle":[{"body":"Hello2","handler":"static_response"}],"match":[{"path":["/route_1/*"]}]}]}}}}}`+"\n")

	// Try to add another copy of route2 using POST to test duplicate ID handling
	// Since the first route2 ended up at array index 0, and we are appending to the array, the index for the new element would be 2
	tester.AssertPostResponseBody(
		"http://localhost:2999/id/route2",
		headers,
		bytes.NewBuffer(route2),
		400,
		`{"error":"indexing config: duplicate ID 'route2' found at /config/apps/http/servers/s_server/routes/0 and /config/apps/http/servers/s_server/routes/2"}`+"\n")

	// Use PATCH to modify an existing object successfully
	tester.AssertPatchResponseBody(
		"http://localhost:2999/id/route1",
		headers,
		bytes.NewBuffer([]byte(`{"@id":"route1","handle":[{"handler":"static_response","body":"route1"}],"match":[{"path":["/route_1/*"]}]}`)),
		200,
		"")

	// Verify the PATCH updated the server state
	tester.AssertGetResponse(
		"http://localhost:9080/route_1/",
		200,
		"route1")
}
