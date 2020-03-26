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
			"_servers": [
				{
					"listen": [
						":80"
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
			]
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
			"_servers": [
				{
					"listen": [
						":80"
					],
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
			]
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
			"_servers": [
				{
					"listen": [
						":443"
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
							"match": [
								{
									"host": [
										"a.caddy.localhost"
									]
								}
							],
							"terminal": true
						}
					]
				}
			]
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
			"_servers": [
				{
					"automatic_https": {
						"skip": [
							"a.caddy.localhost"
						]
					},
					"listen": [
						":80"
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
							"match": [
								{
									"host": [
										"a.caddy.localhost"
									]
								}
							],
							"terminal": true
						}
					]
				}
			]
		}
	}
}`)
}

func TestHttpOnlyOnDomainWithSNI(t *testing.T) {
	caddytest.AssertAdapt(t, `
	{
		default_sni a.caddy.localhost
	}
	:80 {
		respond /version 200 {
			body "hello from localhost"
		}
	}
  `, "caddyfile", `{
	"apps": {
		"http": {
			"_servers": [
				{
					"listen": [
						":80"
					],
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
			]
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
			"_servers": [
				{
					"automatic_https": {
						"skip": [
							"a.caddy.localhost"
						]
					},
					"listen": [
						":81"
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
							"match": [
								{
									"host": [
										"a.caddy.localhost"
									]
								}
							],
							"terminal": true
						}
					]
				}
			]
		}
	}
}`)
}

func TestHttpsMultiHostWithAcme(t *testing.T) {
	caddytest.AssertAdapt(t, `
	{  
		default_sni a.caddy.localhost
	}

	a.caddy.localhost, b.caddy.localhost, http://c.caddy.localhost {

		tls admin@example.com

		respond /version 200 {
			body "hello from localhost"
		}
	}
  `, "caddyfile", `{
	"apps": {
		"http": {
			"_servers": [
				{
					"automatic_https": {
						"skip": [
							"c.caddy.localhost"
						]
					},
					"listen": [
						":80"
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
							"match": [
								{
									"host": [
										"c.caddy.localhost"
									]
								}
							],
							"terminal": true
						}
					]
				},
				{
					"listen": [
						":443"
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
							"match": [
								{
									"host": [
										"a.caddy.localhost",
										"b.caddy.localhost"
									]
								}
							],
							"terminal": true
						}
					],
					"tls_connection_policies": [
						{
							"default_sni": "a.caddy.localhost",
							"match": {
								"sni": [
									"a.caddy.localhost",
									"b.caddy.localhost"
								]
							}
						},
						{
							"default_sni": "a.caddy.localhost"
						}
					]
				}
			]
		},
		"tls": {
			"automation": {
				"policies": [
					{
						"issuer": {
							"email": "admin@example.com",
							"module": "acme"
						},
						"subjects": [
							"a.caddy.localhost",
							"b.caddy.localhost",
							"c.caddy.localhost"
						]
					}
				]
			}
		}
	}
}`)
}
