// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package integration

import (
	"crypto/tls"
	"net/http"
	"testing"

	"github.com/caddyserver/caddy/v2/caddytest"
)

func TestTLSServerCertResumedHandshake(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(`{
		"admin": {
			"listen": "localhost:2999"
		},
		"apps": {
			"http": {
				"grace_period": 1,
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
										"body": "{http.request.tls.resumed} {http.request.tls.server.subject}",
										"handler": "static_response"
									}
								],
								"match": [
									{
										"host": [
											"a.caddy.localhost"
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
								},
								"match": {
									"sni": [
										"a.caddy.localhost"
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
			}
		}
	}`, "json")

	tr := tester.Client.Transport.(*http.Transport)
	tr.TLSClientConfig.ClientSessionCache = tls.NewLRUClientSessionCache(10)

	expectedSubject := "CN=*.caddy.localhost,OU=Local Developement,O=Local Developement,L=Local Developement,ST=NY,C=US,1.2.840.113549.1.9.1=admin@caddy.local"

	// First request: full handshake (resumed = false)
	tester.AssertGetResponse("https://a.caddy.localhost:9443", 200, "false "+expectedSubject)

	// Close idle connection to force a new TLS handshake on the next request
	tr.CloseIdleConnections()

	// Second request: resumed handshake (resumed = true)
	tester.AssertGetResponse("https://a.caddy.localhost:9443", 200, "true "+expectedSubject)
}
