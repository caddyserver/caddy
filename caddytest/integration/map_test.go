package integration

import (
	"bytes"
	"testing"

	"github.com/caddyserver/caddy/v2/caddytest"
)

func TestMap(t *testing.T) {
	// arrange
	tester := caddytest.NewTester(t)
	tester.InitServer(`{
		skip_install_trust
		admin localhost:2999
		http_port     9080
		https_port    9443
		grace_period  1ns
	}

	localhost:9080 {

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
	tester.AssertGetResponse("http://localhost:9080/version", 200, "hello from localhost GET-called unknown2")
	tester.AssertPostResponseBody("http://localhost:9080/version", []string{}, bytes.NewBuffer([]byte{}), 200, "hello from localhost post-called foobar")
}

func TestMapRespondWithDefault(t *testing.T) {
	// arrange
	tester := caddytest.NewTester(t)
	tester.InitServer(`{
		skip_install_trust
		admin localhost:2999
		http_port     9080
		https_port    9443
		}
		
		localhost:9080 {
	
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
	tester.AssertGetResponse("http://localhost:9080/version", 200, "hello from localhost get-called")
	tester.AssertPostResponseBody("http://localhost:9080/version", []string{}, bytes.NewBuffer([]byte{}), 200, "hello from localhost unknown")
}

func TestMapAsJSON(t *testing.T) {
	// arrange
	tester := caddytest.NewTester(t)
	tester.InitServer(`
	{
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
					"srv0": {
						"listen": [
							":9080"
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

	tester.AssertGetResponse("http://localhost:9080/version", 200, "hello from localhost get-called")
	tester.AssertPostResponseBody("http://localhost:9080/version", []string{}, bytes.NewBuffer([]byte{}), 200, "hello from localhost post-called")
}
