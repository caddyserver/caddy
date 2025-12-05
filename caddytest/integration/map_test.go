package integration

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/caddyserver/caddy/v2/caddytest"
)

func TestMap(t *testing.T) {
	// arrange
	harness := caddytest.StartHarness(t)
	harness.LoadConfig(`{
		skip_install_trust
		admin {$TESTING_CADDY_ADMIN_BIND}
		http_port     {$TESTING_CADDY_PORT_ONE}
		https_port    {$TESTING_CADDY_PORT_TWO}
		grace_period  1ns
	}

	localhost:{$TESTING_CADDY_PORT_ONE} {

		map {http.request.method} {dest-1} {dest-2} {
			default unknown1    unknown2
			~G(.)(.)    G${1}${2}-called
			POST    post-called foobar
		}

		respond /version 200 {
			body "hello from localhost {dest-1} {dest-2}"
		}
	}
	`, "caddyfile")

	// act and assert
	harness.AssertGetResponse(fmt.Sprintf("http://localhost:%d/version", harness.Tester().PortOne()), 200, "hello from localhost GET-called unknown2")
	harness.AssertPostResponseBody(fmt.Sprintf("http://localhost:%d/version", harness.Tester().PortOne()), []string{}, bytes.NewBuffer([]byte{}), 200, "hello from localhost post-called foobar")
}

func TestMapRespondWithDefault(t *testing.T) {
	// arrange
	harness := caddytest.StartHarness(t)
	harness.LoadConfig(`{
		skip_install_trust
		admin {$TESTING_CADDY_ADMIN_BIND}
		http_port     {$TESTING_CADDY_PORT_ONE}
		https_port    {$TESTING_CADDY_PORT_TWO}
		}

		localhost:{$TESTING_CADDY_PORT_ONE} {

			map {http.request.method} {dest-name} {
				default unknown
				GET     get-called
			}

			respond /version 200 {
				body "hello from localhost {dest-name}"
			}
		}
	`, "caddyfile")

	// act and assert
	harness.AssertGetResponse(fmt.Sprintf("http://localhost:%d/version", harness.Tester().PortOne()), 200, "hello from localhost get-called")
	harness.AssertPostResponseBody(fmt.Sprintf("http://localhost:%d/version", harness.Tester().PortOne()), []string{}, bytes.NewBuffer([]byte{}), 200, "hello from localhost unknown")
}

func TestMapAsJSON(t *testing.T) {
	// arrange
	harness := caddytest.StartHarness(t)
	harness.LoadConfig(`
	{
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
					"srv0": {
						"listen": [
							":{$TESTING_CADDY_PORT_ONE}"
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
														"handler": "map",
														"source": "{http.request.method}",
														"destinations": ["{dest-name}"],
														"defaults": ["unknown"],
														"mappings": [
															{
																"input": "GET",
																"outputs": ["get-called"]
															},
															{
																"input": "POST",
																"outputs": ["post-called"]
															}
														]
													}
												]
											},
											{
												"handle": [
													{
														"body": "hello from localhost {dest-name}",
														"handler": "static_response",
														"status_code": 200
													}
												],
												"match": [
													{
														"path": ["/version"]
													}
												]
											}
										]
									}
								],
								"match": [
									{
										"host": ["localhost"]
									}
								],
								"terminal": true
							}
						]
					}
				}
			}
		}
	}`, "json")
	target := fmt.Sprintf("http://localhost:%d/version", harness.Tester().PortOne())
	harness.AssertGetResponse(target, 200, "hello from localhost get-called")
	harness.AssertPostResponseBody(target, []string{}, bytes.NewBuffer([]byte{}), 200, "hello from localhost post-called")
}
