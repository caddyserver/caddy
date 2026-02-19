package integration

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddytest"
)

func TestSRVReverseProxy(t *testing.T) {
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
				"grace_period": 1,
				"servers": {
					"srv0": {
						"listen": [
							":18080"
						],
						"routes": [
							{
								"handle": [
									{
										"handler": "reverse_proxy",
										"dynamic_upstreams": {
											"source": "srv",
											"name": "srv.host.service.consul"
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
}

func TestDialWithPlaceholderUnix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.SkipNow()
	}

	f, err := os.CreateTemp("", "*.sock")
	if err != nil {
		t.Errorf("failed to create TempFile: %s", err)
		return
	}
	// a hack to get a file name within a valid path to use as socket
	socketName := f.Name()
	os.Remove(f.Name())

	server := http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.Write([]byte("Hello, World!"))
		}),
	}

	unixListener, err := net.Listen("unix", socketName)
	if err != nil {
		t.Errorf("failed to listen on the socket: %s", err)
		return
	}
	go server.Serve(unixListener)
	t.Cleanup(func() {
		server.Close()
	})
	runtime.Gosched() // Allow other goroutines to run

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
				"grace_period": 1,
				"servers": {
					"srv0": {
						"listen": [
							":18080"
						],
						"routes": [
							{
								"handle": [
									{
										"handler": "reverse_proxy",
										"upstreams": [
											{
												"dial": "unix/{http.request.header.X-Caddy-Upstream-Dial}"
											}
										]
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

	req, err := http.NewRequest(http.MethodGet, "http://localhost:18080", nil)
	if err != nil {
		t.Fail()
		return
	}
	req.Header.Set("X-Caddy-Upstream-Dial", socketName)
	tester.AssertResponse(req, 200, "Hello, World!")
}

func TestReverseProxyWithPlaceholderDialAddress(t *testing.T) {
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
				"grace_period": 1,
				"servers": {
					"srv0": {
						"listen": [
							":18080"
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
										"handler": "static_response",
										"body": "Hello, World!"
									}
								],
								"terminal": true
							}
						],
						"automatic_https": {
							"skip": [
								"localhost"
							]
						}
					},
					"srv1": {
						"listen": [
							":9080"
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
	
										"handler": "reverse_proxy",
										"upstreams": [
											{
												"dial": "{http.request.header.X-Caddy-Upstream-Dial}"
											}
										]
									}
								],
								"terminal": true
							}
						],
						"automatic_https": {
							"skip": [
								"localhost"
							]
						}
					}
				}
			}
		}
	}
	`, "json")

	req, err := http.NewRequest(http.MethodGet, "http://localhost:9080", nil)
	if err != nil {
		t.Fail()
		return
	}
	req.Header.Set("X-Caddy-Upstream-Dial", "localhost:18080")
	tester.AssertResponse(req, 200, "Hello, World!")
}

func TestReverseProxyWithPlaceholderTCPDialAddress(t *testing.T) {
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
				"grace_period": 1,
				"servers": {
					"srv0": {
						"listen": [
							":18080"
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
										"handler": "static_response",
										"body": "Hello, World!"
									}
								],
								"terminal": true
							}
						],
						"automatic_https": {
							"skip": [
								"localhost"
							]
						}
					},
					"srv1": {
						"listen": [
							":9080"
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
	
										"handler": "reverse_proxy",
										"upstreams": [
											{
												"dial": "tcp/{http.request.header.X-Caddy-Upstream-Dial}:18080"
											}
										]
									}
								],
								"terminal": true
							}
						],
						"automatic_https": {
							"skip": [
								"localhost"
							]
						}
					}
				}
			}
		}
	}
	`, "json")

	req, err := http.NewRequest(http.MethodGet, "http://localhost:9080", nil)
	if err != nil {
		t.Fail()
		return
	}
	req.Header.Set("X-Caddy-Upstream-Dial", "localhost")
	tester.AssertResponse(req, 200, "Hello, World!")
}

func TestReverseProxyHealthCheck(t *testing.T) {
	// Start lightweight backend servers so they're ready before Caddy's
	// active health checker runs; this avoids a startup race where the
	// health checker probes backends that haven't yet begun accepting
	// connections and marks them unhealthy.
	//
	// This mirrors how health checks are typically used in practice (to a separate
	// backend service) and avoids probing the same Caddy instance while it's still
	// provisioning and not ready to accept connections.

	// backend server that responds to proxied requests
	helloSrv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			_, _ = w.Write([]byte("Hello, World!"))
		}),
	}
	ln0, err := net.Listen("tcp", "127.0.0.1:2020")
	if err != nil {
		t.Fatalf("failed to listen on 127.0.0.1:2020: %v", err)
	}
	go helloSrv.Serve(ln0)
	t.Cleanup(func() { helloSrv.Close(); ln0.Close() })

	// backend server that serves health checks
	healthSrv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			_, _ = w.Write([]byte("ok"))
		}),
	}
	ln1, err := net.Listen("tcp", "127.0.0.1:2021")
	if err != nil {
		t.Fatalf("failed to listen on 127.0.0.1:2021: %v", err)
	}
	go healthSrv.Serve(ln1)
	t.Cleanup(func() { healthSrv.Close(); ln1.Close() })

	tester := caddytest.NewTester(t)
	tester.InitServer(`
	{
		skip_install_trust
		admin localhost:2999
		http_port     9080
		https_port    9443
		grace_period 1ns
	}
	http://localhost:9080 {
		reverse_proxy {
			to localhost:2020
	
			health_uri /health
			health_port 2021
			health_interval 10ms
			health_timeout 100ms
			health_passes 1
			health_fails 1
		}
	}
	`, "caddyfile")
	tester.AssertGetResponse("http://localhost:9080/", 200, "Hello, World!")
}

func TestReverseProxyHealthCheckUnixSocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.SkipNow()
	}
	tester := caddytest.NewTester(t)
	f, err := os.CreateTemp("", "*.sock")
	if err != nil {
		t.Errorf("failed to create TempFile: %s", err)
		return
	}
	// a hack to get a file name within a valid path to use as socket
	socketName := f.Name()
	os.Remove(f.Name())

	server := http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if strings.HasPrefix(req.URL.Path, "/health") {
				w.Write([]byte("ok"))
				return
			}
			w.Write([]byte("Hello, World!"))
		}),
	}

	unixListener, err := net.Listen("unix", socketName)
	if err != nil {
		t.Errorf("failed to listen on the socket: %s", err)
		return
	}
	go server.Serve(unixListener)
	t.Cleanup(func() {
		server.Close()
	})
	runtime.Gosched() // Allow other goroutines to run

	tester.InitServer(fmt.Sprintf(`
	{
		skip_install_trust
		admin localhost:2999
		http_port     9080
		https_port    9443
		grace_period 1ns
	}
	http://localhost:9080 {
		reverse_proxy {
			to unix/%s
	
			health_uri /health
			health_port 2021
			health_interval 2s
			health_timeout 5s
		}
	}
	`, socketName), "caddyfile")

	tester.AssertGetResponse("http://localhost:9080/", 200, "Hello, World!")
}

func TestReverseProxyHealthCheckUnixSocketWithoutPort(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.SkipNow()
	}
	tester := caddytest.NewTester(t)
	f, err := os.CreateTemp("", "*.sock")
	if err != nil {
		t.Errorf("failed to create TempFile: %s", err)
		return
	}
	// a hack to get a file name within a valid path to use as socket
	socketName := f.Name()
	os.Remove(f.Name())

	server := http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if strings.HasPrefix(req.URL.Path, "/health") {
				w.Write([]byte("ok"))
				return
			}
			w.Write([]byte("Hello, World!"))
		}),
	}

	unixListener, err := net.Listen("unix", socketName)
	if err != nil {
		t.Errorf("failed to listen on the socket: %s", err)
		return
	}
	go server.Serve(unixListener)
	t.Cleanup(func() {
		server.Close()
	})
	runtime.Gosched() // Allow other goroutines to run

	tester.InitServer(fmt.Sprintf(`
	{
		skip_install_trust
		admin localhost:2999
		http_port     9080
		https_port    9443
		grace_period 1ns
	}
	http://localhost:9080 {
		reverse_proxy {
			to unix/%s
	
			health_uri /health
			health_interval 2s
			health_timeout 5s
		}
	}
	`, socketName), "caddyfile")

	tester.AssertGetResponse("http://localhost:9080/", 200, "Hello, World!")
}
