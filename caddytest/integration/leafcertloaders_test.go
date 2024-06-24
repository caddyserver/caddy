package integration

import (
	"testing"

	"github.com/caddyserver/caddy/v2/caddytest"
)

func TestLeafCertLoaders(t *testing.T) {
	harness := caddytest.StartHarness(t)
	harness.LoadConfig(`
	{
		"admin": {
			"listen": "{$TESTING_CADDY_ADMIN_BIND}"
		},
		"apps": {
			"http": {
				"http_port": {$TESTING_CADDY_PORT_ONE},
       			"https_port": {$TESTING_CADDY_PORT_TWO},
				"grace_period": 1,
				"servers": {
					"srv0": {
						"listen": [
							":{$TESTING_CADDY_PORT_TWO}"
						],
						"routes": [
							{
								"match": [
									{
										"host": [
											"localhost"
										]
									}
								],
								"terminal": true
							}
						],
						"tls_connection_policies": [
							{
								"client_authentication": {
									"verifiers": [
										{
											"verifier": "leaf",
											"leaf_certs_loaders": [
												{
													"loader": "file",
													"files": ["../leafcert.pem"]
												}, 
												{
													"loader": "folder", 
													"folders": ["../"]
												},
												{
													"loader": "storage"
												},
												{
													"loader": "pem"
												}
											]
										}
									]
								}
							}
						]
					}
				}
			}
		}
	}`, "json")
}
