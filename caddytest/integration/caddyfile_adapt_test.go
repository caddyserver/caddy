package integration

import (
	"testing"

	"github.com/caddyserver/caddy/v2/caddytest"
)

func TestHttpOnlyOnLocalhost(t *testing.T) {
	caddytest.AssertAdapt(t, ` 
	localhost:80 {
		respond /version 200 {
			body "hello from localhost"
		}
	}
  `, "caddyfile", `{
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
							"handle": [
								{
									"handler": "subroute",
									"routes": [
										{
											"handle": [
												{
													"body": "hello from localhost",
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
							"terminal": true
						}
					]
				}
			}
		}
	}
}`)
}

func TestHttpOnlyOnAnyAddress(t *testing.T) {
	caddytest.AssertAdapt(t, ` 
	:80 {
		respond /version 200 {
			body "hello from localhost"
		}
	}
  `, "caddyfile", `{
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
									"path": [
										"/version"
									]
								}
							],
							"handle": [
								{
									"body": "hello from localhost",
									"handler": "static_response",
									"status_code": 200
								}
							]
						}
					]
				}
			}
		}
	}
}`)
}

func TestHttpsOnDomain(t *testing.T) {
	caddytest.AssertAdapt(t, ` 
	a.caddy.localhost {
		respond /version 200 {
			body "hello from localhost"
		}
	}
  `, "caddyfile", `{
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
										"a.caddy.localhost"
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
													"body": "hello from localhost",
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
							"terminal": true
						}
					]
				}
			}
		}
	}
}`)
}

func TestHttpOnlyOnDomain(t *testing.T) {
	caddytest.AssertAdapt(t, ` 
	http://a.caddy.localhost {
		respond /version 200 {
			body "hello from localhost"
		}
	}
  `, "caddyfile", `{
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
										"a.caddy.localhost"
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
													"body": "hello from localhost",
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
							"terminal": true
						}
					],
					"automatic_https": {
						"skip": [
							"a.caddy.localhost"
						]
					}
				}
			}
		}
	}
}`)
}

func TestHttpOnlyOnNonStandardPort(t *testing.T) {
	caddytest.AssertAdapt(t, ` 
	http://a.caddy.localhost:81 {
		respond /version 200 {
			body "hello from localhost"
		}
	}
  `, "caddyfile", `{
	"apps": {
		"http": {
			"servers": {
				"srv0": {
					"listen": [
						":81"
					],
					"routes": [
						{
							"match": [
								{
									"host": [
										"a.caddy.localhost"
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
													"body": "hello from localhost",
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
							"terminal": true
						}
					],
					"automatic_https": {
						"skip": [
							"a.caddy.localhost"
						]
					}
				}
			}
		}
	}
}`)
}

func TestMatcherSyntax(t *testing.T) {
	caddytest.AssertAdapt(t, ` 
	:80 {
		@matcher {
			method GET
		}
		respond @matcher "get"

		@matcher2 method POST
		respond @matcher2 "post"

		@matcher3 not method PUT
		respond @matcher3 "not put"
	}
  `, "caddyfile", `{
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
									"method": [
										"GET"
									]
								}
							],
							"handle": [
								{
									"body": "get",
									"handler": "static_response"
								}
							]
						},
						{
							"match": [
								{
									"method": [
										"POST"
									]
								}
							],
							"handle": [
								{
									"body": "post",
									"handler": "static_response"
								}
							]
						},
						{
							"match": [
								{
									"not": [
										{
											"method": [
												"PUT"
											]
										}
									]
								}
							],
							"handle": [
								{
									"body": "not put",
									"handler": "static_response"
								}
							]
						}
					]
				}
			}
		}
	}
}`)
}

func TestNotBlockMerging(t *testing.T) {
	caddytest.AssertAdapt(t, ` 
	:80

	@test {
		not {
			header Abc "123"
			header Bcd "123"
		}
	}
	respond @test 403
  `, "caddyfile", `{
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
									"not": [
										{
											"header": {
												"Abc": [
													"123"
												],
												"Bcd": [
													"123"
												]
											}
										}
									]
								}
							],
							"handle": [
								{
									"handler": "static_response",
									"status_code": 403
								}
							]
						}
					]
				}
			}
		}
	}
}`)
}

func TestGlobalOptions(t *testing.T) {
	caddytest.AssertAdapt(t, ` 
	{
		debug
		http_port 8080
		https_port 8443
		default_sni localhost
		order root first
		storage file_system {
			root /data
		}
		acme_ca https://example.com
		acme_ca_root /path/to/ca.crt
		email test@example.com
		admin off
		on_demand_tls {
			ask https://example.com
			interval 30s
			burst 20
		}
		local_certs
		key_type ed25519
	}

	:80
  `, "caddyfile", `{
	"admin": {
		"disabled": true
	},
	"logging": {
		"logs": {
			"default": {
				"level": "DEBUG"
			}
		}
	},
	"storage": {
		"module": "file_system",
		"root": "/data"
	},
	"apps": {
		"http": {
			"http_port": 8080,
			"https_port": 8443,
			"servers": {
				"srv0": {
					"listen": [
						":80"
					]
				}
			}
		},
		"tls": {
			"automation": {
				"policies": [
					{
						"issuer": {
							"module": "internal"
						}
					}
				],
				"on_demand": {
					"rate_limit": {
						"interval": 30000000000,
						"burst": 20
					},
					"ask": "https://example.com"
				}
			}
		}
	}
}`)
}

func TestLogRollDays(t *testing.T) {
	caddytest.AssertAdapt(t, ` 
	:80

	log {
		output file /var/log/access.log {
			roll_size 1gb
			roll_keep 5
			roll_keep_for 90d
		}
	}
  `, "caddyfile", `{
	"logging": {
		"logs": {
			"default": {
				"exclude": [
					"http.log.access.log0"
				]
			},
			"log0": {
				"writer": {
					"filename": "/var/log/access.log",
					"output": "file",
					"roll_keep": 5,
					"roll_keep_days": 90,
					"roll_size_mb": 954
				},
				"include": [
					"http.log.access.log0"
				]
			}
		}
	},
	"apps": {
		"http": {
			"servers": {
				"srv0": {
					"listen": [
						":80"
					],
					"logs": {
						"default_logger_name": "log0"
					}
				}
			}
		}
	}
}`)
}

func TestShorthandParameterizedPlaceholders(t *testing.T) {
	caddytest.AssertAdapt(t, `
	localhost:80
	respond * "{header.content-type} {labels.0} {query.p} {path.0} {r.name.0}"
	`, "caddyfile", `{
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
							"handle": [
								{
									"handler": "subroute",
									"routes": [
										{
											"handle": [
												{
													"body": "{http.request.header.content-type} {http.request.host.labels.0} {http.request.uri.query.p} {http.request.uri.path.0} {http.regexp.name.0}",
													"handler": "static_response"
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
}`)
}
