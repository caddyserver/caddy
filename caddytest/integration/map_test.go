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
		http_port     9080
		https_port    9443
	}

	localhost:9080 {

		map http.request.method dest-name {
			default unknown
			G.T get-called
			POST post-called
		}

		respond /version 200 {
			body "hello from localhost {dest-name}"
		}	
	}
	`, "caddyfile")

	// act and assert
	tester.AssertGetResponse("http://localhost:9080/version", 200, "hello from localhost get-called")
	tester.AssertPostResponseBody("http://localhost:9080/version", []string{}, bytes.NewBuffer([]byte{}), 200, "hello from localhost post-called")
}

func TestMapRespondWithDefault(t *testing.T) {

	// arrange
	tester := caddytest.NewTester(t)
	tester.InitServer(`{
		http_port     9080
		https_port    9443
		}
		
		localhost:9080 {
	
			map http.request.method dest-name {
				default unknown
				GET get-called
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

func TestMapAsJson(t *testing.T) {

	// arrange
	tester := caddytest.NewTester(t)
	tester.InitServer(`{
		"apps": {
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
								"source": "http.request.method",
								"destination": "dest-name",
								"default": "unknown",
								"items": [
									{
									"expression": "GET",
									"value": "get-called"
									},
									{
									"expression": "POST",
									"value": "post-called"
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
							"localhost"
						]
						}
					],
					"terminal": true
					}
				]
				}
			}
			}
		}
		}
		`, "json")

	tester.AssertGetResponse("http://localhost:9080/version", 200, "hello from localhost get-called")
	tester.AssertPostResponseBody("http://localhost:9080/version", []string{}, bytes.NewBuffer([]byte{}), 200, "hello from localhost post-called")
}
