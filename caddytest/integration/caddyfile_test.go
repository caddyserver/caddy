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
