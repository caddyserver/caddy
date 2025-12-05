package integration

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/caddyserver/caddy/v2/caddytest"
)

func TestRespond(t *testing.T) {
	// arrange
	harness := caddytest.StartHarness(t)
	harness.LoadConfig(`
  {
    admin {$TESTING_CADDY_ADMIN_BIND}
    http_port     {$TESTING_CADDY_PORT_ONE}
    https_port    {$TESTING_CADDY_PORT_TWO}
    grace_period  1ns
  }

  localhost:{$TESTING_CADDY_PORT_ONE} {
    respond /version 200 {
      body "hello from localhost"
    }
    }
  `, "caddyfile")

	// act and assert
	harness.AssertGetResponse(fmt.Sprintf("http://localhost:%d/version", harness.Tester().PortOne()), 200, "hello from localhost")
}

func TestRedirect(t *testing.T) {
	// arrange
	harness := caddytest.StartHarness(t)
	harness.LoadConfig(`
  {
    admin {$TESTING_CADDY_ADMIN_BIND}
    http_port     {$TESTING_CADDY_PORT_ONE}
    https_port    {$TESTING_CADDY_PORT_TWO}
    grace_period  1ns
  }

  localhost:{$TESTING_CADDY_PORT_ONE} {

    redir / http://localhost:{$TESTING_CADDY_PORT_ONE}/hello 301

    respond /hello 200 {
      body "hello from localhost"
    }
    }
  `, "caddyfile")

	target := fmt.Sprintf("http://localhost:%d/", harness.Tester().PortOne())
	// act and assert
	harness.AssertRedirect(target, target+"hello", 301)

	// follow redirect
	harness.AssertGetResponse(target, 200, "hello from localhost")
}

func TestDuplicateHosts(t *testing.T) {
	// act and assert
	caddytest.AssertLoadError(t,
		`
    localhost:{$TESTING_CADDY_PORT_ONE} {
    }

    localhost:{$TESTING_CADDY_PORT_ONE} {
    }
    `,
		"caddyfile",
		"ambiguous site definition")
}

func TestReadCookie(t *testing.T) {
	localhost, _ := url.Parse("http://localhost")
	cookie := http.Cookie{
		Name:  "clientname",
		Value: "caddytest",
	}

	// arrange
	harness := caddytest.StartHarness(t)
	harness.Client().Jar.SetCookies(localhost, []*http.Cookie{&cookie})
	harness.LoadConfig(`
  {
    skip_install_trust
    admin {$TESTING_CADDY_ADMIN_BIND}
    http_port     {$TESTING_CADDY_PORT_ONE}
    https_port    {$TESTING_CADDY_PORT_TWO}
    grace_period  1ns
  }

  localhost:{$TESTING_CADDY_PORT_ONE} {
    templates {
      root testdata
    }
    file_server {
      root testdata
    }
  }
  `, "caddyfile")

	// act and assert
	target := fmt.Sprintf("http://localhost:%d/", harness.Tester().PortOne())
	harness.AssertGetResponse(target+"cookie.html", 200, "<h2>Cookie.ClientName caddytest</h2>")
}

func TestReplIndex(t *testing.T) {
	harness := caddytest.StartHarness(t)
	harness.LoadConfig(`
  {
    skip_install_trust
    admin {$TESTING_CADDY_ADMIN_BIND}
    http_port     {$TESTING_CADDY_PORT_ONE}
    https_port    {$TESTING_CADDY_PORT_TWO}
    grace_period  1ns
  }

  localhost:{$TESTING_CADDY_PORT_ONE} {
    templates {
      root testdata
    }
    file_server {
      root testdata
      index "index.{host}.html"
    }
  }
  `, "caddyfile")

	// act and assert
	target := fmt.Sprintf("http://localhost:%d/", harness.Tester().PortOne())
	harness.AssertGetResponse(target, 200, "")
}

func TestInvalidPrefix(t *testing.T) {
	type testCase struct {
		config, expectedError string
	}

	failureCases := []testCase{
		{
			config:        `wss://localhost`,
			expectedError: `the scheme wss:// is only supported in browsers; use https:// instead`,
		},
		{
			config:        `ws://localhost`,
			expectedError: `the scheme ws:// is only supported in browsers; use http:// instead`,
		},
		{
			config:        `someInvalidPrefix://localhost`,
			expectedError: "unsupported URL scheme someinvalidprefix://",
		},
		{
			config:        `h2c://localhost`,
			expectedError: `unsupported URL scheme h2c://`,
		},
		{
			config:        `localhost, wss://localhost`,
			expectedError: `the scheme wss:// is only supported in browsers; use https:// instead`,
		},
		{
			config: `localhost {
  				reverse_proxy ws://localhost"
            }`,
			expectedError: `the scheme ws:// is only supported in browsers; use http:// instead`,
		},
		{
			config: `localhost {
  				reverse_proxy someInvalidPrefix://localhost"
			}`,
			expectedError: `unsupported URL scheme someinvalidprefix://`,
		},
	}

	for _, failureCase := range failureCases {
		caddytest.AssertLoadError(t, failureCase.config, "caddyfile", failureCase.expectedError)
	}
}

func TestValidPrefix(t *testing.T) {
	type testCase struct {
		rawConfig, expectedResponse string
	}

	successCases := []testCase{
		{
			"localhost",
			`{
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
					]
				}
			}
		}
	}
}`,
		},
		{
			"https://localhost",
			`{
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
					]
				}
			}
		}
	}
}`,
		},
		{
			"http://localhost",
			`{
	"apps": {
		"http": {
			"servers": {
				"srv0": {
					"listen": [
						":80"
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
					]
				}
			}
		}
	}
}`,
		},
		{
			`localhost {
			reverse_proxy http://localhost:3000
		 }`,
			`{
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
							"handle": [
								{
									"handler": "subroute",
									"routes": [
										{
											"handle": [
												{
													"handler": "reverse_proxy",
													"upstreams": [
														{
															"dial": "localhost:3000"
														}
													]
												}
											]
										}
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
}`,
		},
		{
			`localhost {
			reverse_proxy https://localhost:3000
		 }`,
			`{
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
							"handle": [
								{
									"handler": "subroute",
									"routes": [
										{
											"handle": [
												{
													"handler": "reverse_proxy",
													"transport": {
														"protocol": "http",
														"tls": {}
													},
													"upstreams": [
														{
															"dial": "localhost:3000"
														}
													]
												}
											]
										}
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
}`,
		},
		{
			`localhost {
			reverse_proxy h2c://localhost:3000
		 }`,
			`{
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
							"handle": [
								{
									"handler": "subroute",
									"routes": [
										{
											"handle": [
												{
													"handler": "reverse_proxy",
													"transport": {
														"protocol": "http",
														"versions": [
															"h2c",
															"2"
														]
													},
													"upstreams": [
														{
															"dial": "localhost:3000"
														}
													]
												}
											]
										}
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
}`,
		},
		{
			`localhost {
			reverse_proxy localhost:3000
		 }`,
			`{
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
							"handle": [
								{
									"handler": "subroute",
									"routes": [
										{
											"handle": [
												{
													"handler": "reverse_proxy",
													"upstreams": [
														{
															"dial": "localhost:3000"
														}
													]
												}
											]
										}
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
}`,
		},
	}

	for _, successCase := range successCases {
		caddytest.AssertAdapt(t, successCase.rawConfig, "caddyfile", successCase.expectedResponse)
	}
}

func TestUriReplace(t *testing.T) {
	harness := caddytest.StartHarness(t)

	harness.LoadConfig(`
	{
		admin {$TESTING_CADDY_ADMIN_BIND}
		http_port     {$TESTING_CADDY_PORT_ONE}
	}
	:{$TESTING_CADDY_PORT_ONE}
	uri replace "\}" %7D
	uri replace "\{" %7B

	respond "{query}"`, "caddyfile")

	target := fmt.Sprintf("http://localhost:%d/", harness.Tester().PortOne())
	harness.AssertGetResponse(target+"endpoint?test={%20content%20}", 200, "test=%7B%20content%20%7D")
}

func TestUriOps(t *testing.T) {
	harness := caddytest.StartHarness(t)

	harness.LoadConfig(`
	{
		admin {$TESTING_CADDY_ADMIN_BIND}
		http_port     {$TESTING_CADDY_PORT_ONE}
	}
	:{$TESTING_CADDY_PORT_ONE}
	uri query +foo bar
	uri query -baz
	uri query taz test
	uri query key=value example
	uri query changethis>changed

	respond "{query}"`, "caddyfile")

	target := fmt.Sprintf("http://localhost:%d/", harness.Tester().PortOne())
	harness.AssertGetResponse(target+"endpoint?foo=bar0&baz=buz&taz=nottest&changethis=val", 200, "changed=val&foo=bar0&foo=bar&key%3Dvalue=example&taz=test")
}

// Tests the `http.request.local.port` placeholder.
// We don't test the very similar `http.request.local.host` placeholder,
// because depending on the host the test is running on, localhost might
// refer to 127.0.0.1 or ::1.
// TODO: Test each http version separately (especially http/3)
func TestHttpRequestLocalPortPlaceholder(t *testing.T) {
	harness := caddytest.StartHarness(t)

	harness.LoadConfig(`
	{
		admin {$TESTING_CADDY_ADMIN_BIND}
		http_port     {$TESTING_CADDY_PORT_ONE}
	}
	:{$TESTING_CADDY_PORT_ONE}
	respond "{http.request.local.port}"`, "caddyfile")

	target := fmt.Sprintf("http://localhost:%d/", harness.Tester().PortOne())
	harness.AssertGetResponse(target, 200, fmt.Sprintf("%d", harness.Tester().PortOne()))
}

func TestSetThenAddQueryParams(t *testing.T) {
	harness := caddytest.StartHarness(t)

	harness.LoadConfig(`
	{
		admin {$TESTING_CADDY_ADMIN_BIND}
		http_port     {$TESTING_CADDY_PORT_ONE}
	}
	:{$TESTING_CADDY_PORT_ONE}
	uri query foo bar
	uri query +foo baz

	respond "{query}"`, "caddyfile")

	target := fmt.Sprintf("http://localhost:%d/", harness.Tester().PortOne())
	harness.AssertGetResponse(target+"endpoint", 200, "foo=bar&foo=baz")
}

func TestSetThenDeleteParams(t *testing.T) {
	harness := caddytest.StartHarness(t)

	harness.LoadConfig(`
	{
		admin {$TESTING_CADDY_ADMIN_BIND}
		http_port     {$TESTING_CADDY_PORT_ONE}
	}
	:{$TESTING_CADDY_PORT_ONE}
	uri query bar foo{query.foo}
	uri query -foo

	respond "{query}"`, "caddyfile")

	target := fmt.Sprintf("http://localhost:%d/", harness.Tester().PortOne())
	harness.AssertGetResponse(target+"endpoint?foo=bar", 200, "bar=foobar")
}

func TestRenameAndOtherOps(t *testing.T) {
	harness := caddytest.StartHarness(t)

	harness.LoadConfig(`
	{
		admin {$TESTING_CADDY_ADMIN_BIND}
		http_port     {$TESTING_CADDY_PORT_ONE}
	}
	:{$TESTING_CADDY_PORT_ONE}
	uri query foo>bar
	uri query bar taz
	uri query +bar baz

	respond "{query}"`, "caddyfile")

	target := fmt.Sprintf("http://localhost:%d/", harness.Tester().PortOne())
	harness.AssertGetResponse(target+"endpoint?foo=bar", 200, "bar=taz&bar=baz")
}

func TestReplaceOps(t *testing.T) {
	harness := caddytest.StartHarness(t)

	harness.LoadConfig(`
	{
		admin {$TESTING_CADDY_ADMIN_BIND}
		http_port     {$TESTING_CADDY_PORT_ONE}
	}
	:{$TESTING_CADDY_PORT_ONE}
	uri query foo bar baz
	respond "{query}"`, "caddyfile")

	target := fmt.Sprintf("http://localhost:%d/", harness.Tester().PortOne())
	harness.AssertGetResponse(target+"endpoint?foo=bar", 200, "foo=baz")
}

func TestReplaceWithReplacementPlaceholder(t *testing.T) {
	harness := caddytest.StartHarness(t)
	harness.LoadConfig(`
	{
		admin {$TESTING_CADDY_ADMIN_BIND}
		http_port     {$TESTING_CADDY_PORT_ONE}
	}
	:{$TESTING_CADDY_PORT_ONE}
	uri query foo bar {query.placeholder}
	respond "{query}"`, "caddyfile")

	target := fmt.Sprintf("http://localhost:%d/", harness.Tester().PortOne())
	harness.AssertGetResponse(target+"endpoint?placeholder=baz&foo=bar", 200, "foo=baz&placeholder=baz")
}

func TestReplaceWithKeyPlaceholder(t *testing.T) {
	harness := caddytest.StartHarness(t)
	harness.LoadConfig(`
	{
		admin {$TESTING_CADDY_ADMIN_BIND}
		http_port     {$TESTING_CADDY_PORT_ONE}
	}
	:{$TESTING_CADDY_PORT_ONE}
	uri query {query.placeholder} bar baz
	respond "{query}"`, "caddyfile")

	target := fmt.Sprintf("http://localhost:%d/", harness.Tester().PortOne())
	harness.AssertGetResponse(target+"endpoint?placeholder=foo&foo=bar", 200, "foo=baz&placeholder=foo")
}

func TestPartialReplacement(t *testing.T) {
	harness := caddytest.StartHarness(t)
	harness.LoadConfig(`
	{
		admin {$TESTING_CADDY_ADMIN_BIND}
		http_port     {$TESTING_CADDY_PORT_ONE}
	}
	:{$TESTING_CADDY_PORT_ONE}
	uri query foo ar az
	respond "{query}"`, "caddyfile")

	target := fmt.Sprintf("http://localhost:%d/", harness.Tester().PortOne())
	harness.AssertGetResponse(target+"endpoint?foo=bar", 200, "foo=baz")
}

func TestNonExistingSearch(t *testing.T) {
	harness := caddytest.StartHarness(t)
	harness.LoadConfig(`
	{
		admin {$TESTING_CADDY_ADMIN_BIND}
		http_port     {$TESTING_CADDY_PORT_ONE}
	}
	:{$TESTING_CADDY_PORT_ONE}
	uri query foo var baz
	respond "{query}"`, "caddyfile")

	target := fmt.Sprintf("http://localhost:%d/", harness.Tester().PortOne())
	harness.AssertGetResponse(target+"endpoint?foo=bar", 200, "foo=bar")
}

func TestReplaceAllOps(t *testing.T) {
	harness := caddytest.StartHarness(t)

	harness.LoadConfig(`
	{
		admin {$TESTING_CADDY_ADMIN_BIND}
		http_port     {$TESTING_CADDY_PORT_ONE}
	}
	:{$TESTING_CADDY_PORT_ONE}
	uri query * bar baz
	respond "{query}"`, "caddyfile")

	target := fmt.Sprintf("http://localhost:%d/", harness.Tester().PortOne())
	harness.AssertGetResponse(target+"endpoint?foo=bar&baz=bar", 200, "baz=baz&foo=baz")
}

func TestUriOpsBlock(t *testing.T) {
	harness := caddytest.StartHarness(t)

	harness.LoadConfig(`
	{
		admin {$TESTING_CADDY_ADMIN_BIND}
		http_port     {$TESTING_CADDY_PORT_ONE}
	}
	:{$TESTING_CADDY_PORT_ONE}
	uri query {
		+foo bar
		-baz
		taz test
	}
	respond "{query}"`, "caddyfile")

	target := fmt.Sprintf("http://localhost:%d/", harness.Tester().PortOne())
	harness.AssertGetResponse(target+"endpoint?foo=bar0&baz=buz&taz=nottest", 200, "foo=bar0&foo=bar&taz=test")
}

func TestHandleErrorSimpleCodes(t *testing.T) {
	harness := caddytest.StartHarness(t)
	harness.LoadConfig(`{
		admin {$TESTING_CADDY_ADMIN_BIND}
		http_port     {$TESTING_CADDY_PORT_ONE}
	}
	localhost:{$TESTING_CADDY_PORT_ONE} {
		root * /srv
		error /private* "Unauthorized" 410
		error /hidden* "Not found" 404

		handle_errors 404 410 {
			respond "404 or 410 error"
		}
	}`, "caddyfile")
	// act and assert
	target := fmt.Sprintf("http://localhost:%d/", harness.Tester().PortOne())
	harness.AssertGetResponse(target+"private", 410, "404 or 410 error")
	harness.AssertGetResponse(target+"hidden", 404, "404 or 410 error")
}

func TestHandleErrorRange(t *testing.T) {
	harness := caddytest.StartHarness(t)
	harness.LoadConfig(`{
		admin {$TESTING_CADDY_ADMIN_BIND}
		http_port     {$TESTING_CADDY_PORT_ONE}
	}
	localhost:{$TESTING_CADDY_PORT_ONE} {
		root * /srv
		error /private* "Unauthorized" 410
		error /hidden* "Not found" 404

		handle_errors 4xx {
			respond "Error in the [400 .. 499] range"
		}
	}`, "caddyfile")
	// act and assert
	target := fmt.Sprintf("http://localhost:%d/", harness.Tester().PortOne())
	harness.AssertGetResponse(target+"private", 410, "Error in the [400 .. 499] range")
	harness.AssertGetResponse(target+"hidden", 404, "Error in the [400 .. 499] range")
}

func TestHandleErrorSort(t *testing.T) {
	harness := caddytest.StartHarness(t)
	harness.LoadConfig(`{
		admin {$TESTING_CADDY_ADMIN_BIND}
		http_port     {$TESTING_CADDY_PORT_ONE}
	}
	localhost:{$TESTING_CADDY_PORT_ONE} {
		root * /srv
		error /private* "Unauthorized" 410
		error /hidden* "Not found" 404
		error /internalerr* "Internal Server Error" 500

		handle_errors {
			respond "Fallback route: code outside the [400..499] range"
		}
		handle_errors 4xx {
			respond "Error in the [400 .. 499] range"
		}
	}`, "caddyfile")
	// act and assert
	target := fmt.Sprintf("http://localhost:%d/", harness.Tester().PortOne())
	harness.AssertGetResponse(target+"internalerr", 500, "Fallback route: code outside the [400..499] range")
	harness.AssertGetResponse(target+"hidden", 404, "Error in the [400 .. 499] range")
}

func TestHandleErrorRangeAndCodes(t *testing.T) {
	harness := caddytest.StartHarness(t)
	harness.LoadConfig(`{
		admin {$TESTING_CADDY_ADMIN_BIND}
		http_port     {$TESTING_CADDY_PORT_ONE}
	}
	localhost:{$TESTING_CADDY_PORT_ONE} {
		root * /srv
		error /private* "Unauthorized" 410
		error /threehundred* "Moved Permanently" 301
		error /internalerr* "Internal Server Error" 500

		handle_errors 500 3xx {
			respond "Error code is equal to 500 or in the [300..399] range"
		}
		handle_errors 4xx {
			respond "Error in the [400 .. 499] range"
		}
	}`, "caddyfile")
	// act and assert
	target := fmt.Sprintf("http://localhost:%d/", harness.Tester().PortOne())
	harness.AssertGetResponse(target+"internalerr", 500, "Error code is equal to 500 or in the [300..399] range")
	harness.AssertGetResponse(target+"threehundred", 301, "Error code is equal to 500 or in the [300..399] range")
	harness.AssertGetResponse(target+"private", 410, "Error in the [400 .. 499] range")
}

func TestHandleErrorSubHandlers(t *testing.T) {
	harness := caddytest.StartHarness(t)
	harness.LoadConfig(`{
		admin localhost:2999
		http_port     9080
	}
	localhost:9080 {
		root * /srv
		file_server
		error /*/internalerr* "Internal Server Error" 500

		handle_errors 404 {
			handle /en/* {
				respond "not found" 404
			}
			handle /es/* {
				respond "no encontrado" 404
			}
			handle {
				respond "default not found"
			}
		}
		handle_errors {
			handle {
				respond "Default error"
			}
			handle /en/* {
				respond "English error"
			}
		}
	}
	`, "caddyfile")
	// act and assert
	harness.AssertGetResponse("http://localhost:9080/en/notfound", 404, "not found")
	harness.AssertGetResponse("http://localhost:9080/es/notfound", 404, "no encontrado")
	harness.AssertGetResponse("http://localhost:9080/notfound", 404, "default not found")
	harness.AssertGetResponse("http://localhost:9080/es/internalerr", 500, "Default error")
	harness.AssertGetResponse("http://localhost:9080/en/internalerr", 500, "English error")
}

func TestInvalidSiteAddressesAsDirectives(t *testing.T) {
	type testCase struct {
		config, expectedError string
	}

	failureCases := []testCase{
		{
			config: `
			handle {
				file_server
			}`,
			expectedError: `Caddyfile:2: parsed 'handle' as a site address, but it is a known directive; directives must appear in a site block`,
		},
		{
			config: `
			reverse_proxy localhost:9000 localhost:9001 {
				file_server
			}`,
			expectedError: `Caddyfile:2: parsed 'reverse_proxy' as a site address, but it is a known directive; directives must appear in a site block`,
		},
	}

	for _, failureCase := range failureCases {
		caddytest.AssertLoadError(t, failureCase.config, "caddyfile", failureCase.expectedError)
	}
}
