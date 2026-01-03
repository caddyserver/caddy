package integration

import (
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/caddyserver/caddy/v2/caddytest"
)

func TestAuthentication(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(`
	{
		"admin": {
			"listen": "localhost:2999"
		},
		"apps": {
			"pki": {
				"certificate_authorities": {
					"local": {
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
								"match": [
									{
										"path": [
											"/basic"
										]
									}
								],
								"handle": [
									{
										"handler": "authentication",
										"providers": {
											"http_basic": {
												"hash_cache": {},
												"accounts": [
													{
														"username": "Aladdin",
														"password": "$2a$14$U5nG2p.Ac09gzn9oo5aRe.YnsXn30UdXA6pRUn45KFqADG636dRHa"
													}
												]
											}
										}
									}
								]
							},
							{
								"match": [
									{
										"path": [
											"/proxy"
										]
									}
								],
								"handle": [
									{
										"handler": "authentication",
										"status_code": 407,
										"providers": {
											"http_basic": {
												"hash_cache": {},
												"authorization_header": "Proxy-Authorization",
												"authenticate_header": "Proxy-Authenticate",
												"realm": "HTTP proxy",
												"accounts": [
													{
														"username": "Aladdin",
														"password": "$2a$14$U5nG2p.Ac09gzn9oo5aRe.YnsXn30UdXA6pRUn45KFqADG636dRHa"
													}
												]
											}
										}
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

	assertHeader := func(tb testing.TB, resp *http.Response, header, want string) {
		if actual := resp.Header.Get(header); actual != want {
			tb.Errorf("expected %s header to be %s, but was %s", header, want, actual)
		}
	}

	resp, _ := tester.AssertGetResponse("http://localhost:9080/basic", http.StatusUnauthorized, "")
	assertHeader(t, resp, "WWW-Authenticate", `Basic realm="restricted"`)

	tester.AssertGetResponse("http://Aladdin:open%20sesame@localhost:9080/basic", http.StatusOK, "")

	tester.AssertGetResponse("http://localhost:9080/proxy", http.StatusProxyAuthRequired, "")

	resp, _ = tester.AssertGetResponse("http://Aladdin:open%20sesame@localhost:9080/proxy", http.StatusProxyAuthRequired, "")
	assertHeader(t, resp, "Proxy-Authenticate", `Basic realm="HTTP proxy"`)

	req, err := http.NewRequest(http.MethodGet, "http://localhost:9080/proxy", nil)
	if err != nil {
		t.Fatalf("unable to create request %v", err)
	}
	req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("Aladdin:open sesame")))
	tester.AssertResponseCode(req, http.StatusOK)
}
