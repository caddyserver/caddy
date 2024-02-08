package integration

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/caddyserver/caddy/v2/caddytest"
)

func TestRespond(t *testing.T) {
	// arrange
	tester := caddytest.NewTester(t)
	tester.InitServer(` 
  {
    admin localhost:2999
    http_port     9080
    https_port    9443
    grace_period  1ns
  }
  
  localhost:9080 {
    respond /version 200 {
      body "hello from localhost"
    }	
    }
  `, "caddyfile")

	// act and assert
	tester.AssertGetResponse("http://localhost:9080/version", 200, "hello from localhost")
}

func TestRedirect(t *testing.T) {
	// arrange
	tester := caddytest.NewTester(t)
	tester.InitServer(`
  {
    admin localhost:2999
    http_port     9080
    https_port    9443
    grace_period  1ns
  }
  
  localhost:9080 {
    
    redir / http://localhost:9080/hello 301
    
    respond /hello 200 {
      body "hello from localhost"
    }	
    }
  `, "caddyfile")

	// act and assert
	tester.AssertRedirect("http://localhost:9080/", "http://localhost:9080/hello", 301)

	// follow redirect
	tester.AssertGetResponse("http://localhost:9080/", 200, "hello from localhost")
}

func TestDuplicateHosts(t *testing.T) {
	// act and assert
	caddytest.AssertLoadError(t,
		`
    localhost:9080 {
    }
  
    localhost:9080 { 
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
	tester := caddytest.NewTester(t)
	tester.Client.Jar.SetCookies(localhost, []*http.Cookie{&cookie})
	tester.InitServer(` 
  {
    skip_install_trust
    admin localhost:2999
    http_port     9080
    https_port    9443
    grace_period  1ns
  }
  
  localhost:9080 {
    templates {
      root testdata
    }
    file_server {
      root testdata
    }
  }
  `, "caddyfile")

	// act and assert
	tester.AssertGetResponse("http://localhost:9080/cookie.html", 200, "<h2>Cookie.ClientName caddytest</h2>")
}

func TestReplIndex(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(`
  {
    skip_install_trust
    admin localhost:2999
    http_port     9080
    https_port    9443
    grace_period  1ns
  }

  localhost:9080 {
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
	tester.AssertGetResponse("http://localhost:9080/", 200, "")
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
	tester := caddytest.NewTester(t)

	tester.InitServer(`
	{
		admin localhost:2999
		http_port     9080
	}
	:9080
	uri replace "\}" %7D
	uri replace "\{" %7B
	
	respond "{query}"`, "caddyfile")

	tester.AssertGetResponse("http://localhost:9080/endpoint?test={%20content%20}", 200, "test=%7B%20content%20%7D")
}
func TestHandleErrorSimpleCodes(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(`{
		admin localhost:2999
		http_port     9080
	}
	localhost:9080 {
		root * /srv
		error /private* "Unauthorized" 410
		error /hidden* "Not found" 404
	
		handle_errors 404 410 {
			respond "404 or 410 error"
		}
	}`, "caddyfile")
	// act and assert
	tester.AssertGetResponse("http://localhost:9080/private", 410, "404 or 410 error")
	tester.AssertGetResponse("http://localhost:9080/hidden", 404, "404 or 410 error")
}

func TestHandleErrorRange(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(`{
		admin localhost:2999
		http_port     9080
	}
	localhost:9080 {
		root * /srv
		error /private* "Unauthorized" 410
		error /hidden* "Not found" 404

		handle_errors 4xx {
			respond "Error in the [400 .. 499] range"
		}
	}`, "caddyfile")
	// act and assert
	tester.AssertGetResponse("http://localhost:9080/private", 410, "Error in the [400 .. 499] range")
	tester.AssertGetResponse("http://localhost:9080/hidden", 404, "Error in the [400 .. 499] range")
}

func TestHandleErrorSort(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(`{
		admin localhost:2999
		http_port     9080
	}
	localhost:9080 {
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
	tester.AssertGetResponse("http://localhost:9080/internalerr", 500, "Fallback route: code outside the [400..499] range")
	tester.AssertGetResponse("http://localhost:9080/hidden", 404, "Error in the [400 .. 499] range")
}

func TestHandleErrorRangeAndCodes(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(`{
		admin localhost:2999
		http_port     9080
	}
	localhost:9080 {
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
	tester.AssertGetResponse("http://localhost:9080/internalerr", 500, "Error code is equal to 500 or in the [300..399] range")
	tester.AssertGetResponse("http://localhost:9080/threehundred", 301, "Error code is equal to 500 or in the [300..399] range")
	tester.AssertGetResponse("http://localhost:9080/private", 410, "Error in the [400 .. 499] range")
}
