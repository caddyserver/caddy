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
