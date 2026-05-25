package integration

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddytest"
	"github.com/quic-go/quic-go/http3"
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

// TestReverseProxyHealthCheckPortUsed verifies that health_port is actually
// used for active health checks and not the upstream's main port. This is a
// regression test for https://github.com/caddyserver/caddy/issues/7524.
func TestReverseProxyHealthCheckPortUsed(t *testing.T) {
	// upstream server: serves proxied requests normally, but returns 503 for
	// /health so that if health checks mistakenly hit this port the upstream
	// gets marked unhealthy and the proxy returns 503.
	upstreamSrv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if req.URL.Path == "/health" {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			_, _ = w.Write([]byte("Hello, World!"))
		}),
	}
	ln0, err := net.Listen("tcp", "127.0.0.1:2022")
	if err != nil {
		t.Fatalf("failed to listen on 127.0.0.1:2022: %v", err)
	}
	go upstreamSrv.Serve(ln0)
	t.Cleanup(func() { upstreamSrv.Close(); ln0.Close() })

	// separate health check server on the configured health_port: returns 200
	// so the upstream is marked healthy only if health checks go to this port.
	healthSrv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			_, _ = w.Write([]byte("ok"))
		}),
	}
	ln1, err := net.Listen("tcp", "127.0.0.1:2023")
	if err != nil {
		t.Fatalf("failed to listen on 127.0.0.1:2023: %v", err)
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
			to localhost:2022

			health_uri /health
			health_port 2023
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

// TestReverseProxyRetryMatchStatusCode verifies that lb_retry_match with a
// CEL expression matching on {rp.status_code} causes the request to be
// retried on the next upstream when the first upstream returns a matching
// status code
func TestReverseProxyRetryMatchStatusCode(t *testing.T) {
	// Bad upstream: returns 502
	badSrv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadGateway)
		}),
	}
	badLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	go badSrv.Serve(badLn)
	t.Cleanup(func() { badSrv.Close(); badLn.Close() })

	// Good upstream: returns 200
	goodSrv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("ok"))
		}),
	}
	goodLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	go goodSrv.Serve(goodLn)
	t.Cleanup(func() { goodSrv.Close(); goodLn.Close() })

	tester := caddytest.NewTester(t)
	tester.InitServer(fmt.Sprintf(`
	{
		skip_install_trust
		admin localhost:2999
		http_port 9080
		https_port 9443
		grace_period 1ns
	}
	http://localhost:9080 {
		reverse_proxy %s %s {
			lb_policy round_robin
			lb_retries 1
			lb_retry_match {
				expression `+"`{rp.status_code} in [502, 503]`"+`
			}
		}
	}
	`, goodLn.Addr().String(), badLn.Addr().String()), "caddyfile")

	tester.AssertGetResponse("http://localhost:9080/", 200, "ok")
}

// TestReverseProxyRetryMatchHeader verifies that lb_retry_match with a CEL
// expression matching on {rp.header.*} causes the request to be retried when
// the upstream sets a matching response header
func TestReverseProxyRetryMatchHeader(t *testing.T) {
	var badHits atomic.Int32

	// Bad upstream: returns 200 but signals retry via header
	badSrv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			badHits.Add(1)
			w.Header().Set("X-Upstream-Retry", "true")
			w.Write([]byte("bad"))
		}),
	}
	badLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	go badSrv.Serve(badLn)
	t.Cleanup(func() { badSrv.Close(); badLn.Close() })

	// Good upstream: returns 200 without retry header
	goodSrv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("good"))
		}),
	}
	goodLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	go goodSrv.Serve(goodLn)
	t.Cleanup(func() { goodSrv.Close(); goodLn.Close() })

	tester := caddytest.NewTester(t)
	tester.InitServer(fmt.Sprintf(`
	{
		skip_install_trust
		admin localhost:2999
		http_port 9080
		https_port 9443
		grace_period 1ns
	}
	http://localhost:9080 {
		reverse_proxy %s %s {
			lb_policy round_robin
			lb_retries 1
			lb_retry_match {
				expression `+"`{rp.header.X-Upstream-Retry} == \"true\"`"+`
			}
		}
	}
	`, goodLn.Addr().String(), badLn.Addr().String()), "caddyfile")

	tester.AssertGetResponse("http://localhost:9080/", 200, "good")

	if badHits.Load() != 1 {
		t.Errorf("bad upstream hits: got %d, want 1", badHits.Load())
	}
}

// TestReverseProxyRetryMatchCombined verifies that a CEL expression combining
// request path matching with response status code matching works correctly -
// only retrying when both conditions are met
func TestReverseProxyRetryMatchCombined(t *testing.T) {
	// Upstream: returns 502 for all requests
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadGateway)
		}),
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close(); ln.Close() })

	// Good upstream
	goodSrv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("ok"))
		}),
	}
	goodLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	go goodSrv.Serve(goodLn)
	t.Cleanup(func() { goodSrv.Close(); goodLn.Close() })

	tester := caddytest.NewTester(t)
	tester.InitServer(fmt.Sprintf(`
	{
		skip_install_trust
		admin localhost:2999
		http_port 9080
		https_port 9443
		grace_period 1ns
	}
	http://localhost:9080 {
		reverse_proxy %s %s {
			lb_policy round_robin
			lb_retries 1
			lb_retry_match {
				expression `+"`path('/retry*') && {rp.status_code} in [502, 503]`"+`
			}
		}
	}
	`, goodLn.Addr().String(), ln.Addr().String()), "caddyfile")

	// /retry path matches the expression - should retry to good upstream
	tester.AssertGetResponse("http://localhost:9080/retry", 200, "ok")

	// /other path does NOT match - should return the 502
	req, _ := http.NewRequest(http.MethodGet, "http://localhost:9080/other", nil)
	tester.AssertResponse(req, 502, "")
}

// TestReverseProxyRetryMatchIsTransportError verifies that the
// {rp.is_transport_error} == true CEL function correctly identifies transport errors
// and allows retrying them alongside response-based matching
func TestReverseProxyRetryMatchIsTransportError(t *testing.T) {
	// Good upstream: returns 200
	goodSrv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("ok"))
		}),
	}
	goodLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	go goodSrv.Serve(goodLn)
	t.Cleanup(func() { goodSrv.Close(); goodLn.Close() })

	// Broken upstream: accepts connections but closes immediately
	brokenLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	t.Cleanup(func() { brokenLn.Close() })
	go func() {
		for {
			conn, err := brokenLn.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	tester := caddytest.NewTester(t)
	tester.InitServer(fmt.Sprintf(`
	{
		skip_install_trust
		admin localhost:2999
		http_port 9080
		https_port 9443
		grace_period 1ns
	}
	http://localhost:9080 {
		reverse_proxy %s %s {
			lb_policy round_robin
			lb_retries 1
			lb_retry_match {
				expression `+"`{rp.is_transport_error} || {rp.status_code} in [502, 503]`"+`
			}
		}
	}
	`, goodLn.Addr().String(), brokenLn.Addr().String()), "caddyfile")

	// Transport error on broken upstream should be retried to good upstream
	tester.AssertGetResponse("http://localhost:9080/", 200, "ok")
}

func TestReverseProxyHTTP3SNIPlaceholderHost(t *testing.T) {
	const expectedSNI = "app.test.local"

	upstreamAddr, gotSNI := startHTTP3SNITestServer(t)

	tester := caddytest.NewTester(t)
	tester.InitServer(fmt.Sprintf(`
	{
		skip_install_trust
		admin localhost:2999
		http_port 9080
		grace_period 1ns
	}
:9080 {
		reverse_proxy https://%s {
			transport http {
				versions 3
				tls_server_name {host}
				tls_insecure_skip_verify
			}
		}
	}
	`, upstreamAddr), "caddyfile")

	req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:9080/", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Host = expectedSNI

	tester.AssertResponse(req, 200, "ok")

	select {
	case sni := <-gotSNI:
		if sni != expectedSNI {
			t.Fatalf("HTTP/3 upstream SNI = %q, want %q", sni, expectedSNI)
		}
		if sni == "{http.request.host}" {
			t.Fatal("HTTP/3 upstream SNI was not expanded from the adapted placeholder")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for HTTP/3 upstream SNI")
	}
}

func startHTTP3SNITestServer(t *testing.T) (string, <-chan string) {
	t.Helper()

	gotSNI := make(chan string, 1)
	udpConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen for HTTP/3 upstream: %v", err)
	}

	server := &http3.Server{
		TLSConfig: http3SNITestTLSConfig(t, func(sni string) {
			select {
			case gotSNI <- sni:
			default:
			}
		}),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprint(w, "ok")
		}),
	}

	done := make(chan struct{})
	errs := make(chan error, 1)
	go func() {
		defer close(done)
		err := server.Serve(udpConn)
		if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			errs <- err
		}
	}()

	t.Cleanup(func() {
		_ = server.Close()
		_ = udpConn.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("timed out waiting for HTTP/3 upstream server to stop")
		}
		select {
		case err := <-errs:
			t.Errorf("HTTP/3 upstream server failed: %v", err)
		default:
		}
	})

	return udpConn.LocalAddr().String(), gotSNI
}

func http3SNITestTLSConfig(t *testing.T, recordSNI func(string)) *tls.Config {
	t.Helper()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate HTTP/3 upstream private key: %v", err)
	}

	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "HTTP/3 SNI test upstream",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		DNSNames:              []string{"app.test.local"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, publicKey, privateKey)
	if err != nil {
		t.Fatalf("failed to create HTTP/3 upstream certificate: %v", err)
	}
	cert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  privateKey,
	}
	baseConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			recordSNI(hello.ServerName)
			return baseConfig.Clone(), nil
		},
	}
}
