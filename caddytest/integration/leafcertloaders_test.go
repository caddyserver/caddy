package integration

import (
	"testing"

	"github.com/caddyserver/caddy/v2/caddytest"
)

func TestLeafCertLoaders(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(`
	{
		"admin": {
			"listen": "localhost:2999"
		},
		"apps": {
			"http": {
				"servers": {
					"srv0": {
						"listen": [
							":443"
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
