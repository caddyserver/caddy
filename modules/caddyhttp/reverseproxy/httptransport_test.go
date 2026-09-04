package reverseproxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/internal/network"
)

func TestHTTPTransportUnmarshalCaddyFileWithCaPools(t *testing.T) {
	const test_der_1 = `MIIDSzCCAjOgAwIBAgIUfIRObjWNUA4jxQ/0x8BOCvE2Vw4wDQYJKoZIhvcNAQELBQAwFjEUMBIGA1UEAwwLRWFzeS1SU0EgQ0EwHhcNMTkwODI4MTYyNTU5WhcNMjkwODI1MTYyNTU5WjAWMRQwEgYDVQQDDAtFYXN5LVJTQSBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK5m5elxhQfMp/3aVJ4JnpN9PUSz6LlP6LePAPFU7gqohVVFVtDkChJAG3FNkNQNlieVTja/bgH9IcC6oKbROwdY1h0MvNV8AHHigvl03WuJD8g2ReVFXXwsnrPmKXCFzQyMI6TYk3m2gYrXsZOU1GLnfMRC3KAMRgE2F45twOs9hqG169YJ6mM2eQjzjCHWI6S2/iUYvYxRkCOlYUbLsMD/AhgAf1plzg6LPqNxtdlwxZnA0ytgkmhK67HtzJu0+ovUCsMv0RwcMhsEo9T8nyFAGt9XLZ63X5WpBCTUApaAUhnG0XnerjmUWb6eUWw4zev54sEfY5F3x002iQaW6cECAwEAAaOBkDCBjTAdBgNVHQ4EFgQU4CBUbZsS2GaNIkGRz/cBsD5ivjswUQYDVR0jBEowSIAU4CBUbZsS2GaNIkGRz/cBsD5ivjuhGqQYMBYxFDASBgNVBAMMC0Vhc3ktUlNBIENBghR8hE5uNY1QDiPFD/THwE4K8TZXDjAMBgNVHRMEBTADAQH/MAsGA1UdDwQEAwIBBjANBgkqhkiG9w0BAQsFAAOCAQEAKB3V4HIzoiO/Ch6WMj9bLJ2FGbpkMrcb/Eq01hT5zcfKD66lVS1MlK+cRL446Z2b2KDP1oFyVs+qmrmtdwrWgD+nfe2sBmmIHo9m9KygMkEOfG3MghGTEcS+0cTKEcoHYWYyOqQh6jnedXY8Cdm4GM1hAc9MiL3/sqV8YCVSLNnkoNysmr06/rZ0MCUZPGUtRmfd0heWhrfzAKw2HLgX+RAmpOE2MZqWcjvqKGyaRiaZks4nJkP6521aC2Lgp0HhCz1j8/uQ5ldoDszCnu/iro0NAsNtudTMD+YoLQxLqdleIh6CW+illc2VdXwj7mn6J04yns9jfE2jRjW/yTLFuQ==`
	type args struct {
		d *caddyfile.Dispenser
	}
	tests := []struct {
		name              string
		args              args
		expectedTLSConfig TLSConfig
		wantErr           bool
	}{
		{
			name: "tls_trust_pool without a module argument returns an error",
			args: args{
				d: caddyfile.NewTestDispenser(
					`http {
					tls_trust_pool
				}`),
			},
			wantErr: true,
		},
		{
			name: "providing both 'tls_trust_pool' and 'tls_trusted_ca_certs' returns an error",
			args: args{
				d: caddyfile.NewTestDispenser(fmt.Sprintf(
					`http {
					tls_trust_pool inline %s
					tls_trusted_ca_certs %s
				}`, test_der_1, test_der_1)),
			},
			wantErr: true,
		},
		{
			name: "setting 'tls_trust_pool' and 'tls_trusted_ca_certs' produces an error",
			args: args{
				d: caddyfile.NewTestDispenser(fmt.Sprintf(
					`http {
					tls_trust_pool inline {
						trust_der	%s
					}
					tls_trusted_ca_certs %s
				}`, test_der_1, test_der_1)),
			},
			wantErr: true,
		},
		{
			name: "using 'inline' tls_trust_pool loads the module successfully",
			args: args{
				d: caddyfile.NewTestDispenser(fmt.Sprintf(
					`http {
						tls_trust_pool inline {
							trust_der	%s
						}
					}
				`, test_der_1)),
			},
			expectedTLSConfig: TLSConfig{CARaw: json.RawMessage(fmt.Sprintf(`{"provider":"inline","trusted_ca_certs":["%s"]}`, test_der_1))},
		},
		{
			name: "setting 'tls_trusted_ca_certs' and 'tls_trust_pool' produces an error",
			args: args{
				d: caddyfile.NewTestDispenser(fmt.Sprintf(
					`http {
						tls_trusted_ca_certs %s
						tls_trust_pool inline {
							trust_der	%s
						}
				}`, test_der_1, test_der_1)),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ht := &HTTPTransport{}
			if err := ht.UnmarshalCaddyfile(tt.args.d); (err != nil) != tt.wantErr {
				t.Errorf("HTTPTransport.UnmarshalCaddyfile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !reflect.DeepEqual(&tt.expectedTLSConfig, ht.TLS) {
				t.Errorf("HTTPTransport.UnmarshalCaddyfile() = %v, want %v", ht, tt.expectedTLSConfig)
			}
		})
	}
}

func TestHTTPTransport_RequestHeaderOps_TLS(t *testing.T) {
	var ht HTTPTransport
	// When TLS is nil, expect no header ops
	if ops := ht.RequestHeaderOps(); ops != nil {
		t.Fatalf("expected nil HeaderOps when TLS is nil, got: %#v", ops)
	}

	// When TLS is configured, expect a HeaderOps that sets Host
	ht.TLS = &TLSConfig{}
	ops := ht.RequestHeaderOps()
	if ops == nil {
		t.Fatal("expected non-nil HeaderOps when TLS is set")
	}
	if ops.Set == nil {
		t.Fatalf("expected ops.Set to be non-nil, got nil")
	}
	if got := ops.Set.Get("Host"); got != "{http.reverse_proxy.upstream.hostport}" {
		t.Fatalf("unexpected Host value; want placeholder, got: %s", got)
	}
}

// TestHTTPTransport_DialTLSContext_ProxyProtocol verifies that when TLS and
// ProxyProtocol are both enabled, DialTLSContext is set. This is critical because
// ProxyProtocol modifies req.URL.Host to include client info with "->" separator
// (e.g., "[2001:db8::1]:12345->127.0.0.1:443"), which breaks Go's address parsing.
// Without a custom DialTLSContext, Go's HTTP library would fail with
// "too many colons in address" when trying to parse the mangled host.
func TestHTTPTransport_DialTLSContext_ProxyProtocol(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	tests := []struct {
		name                     string
		tls                      *TLSConfig
		proxyProtocol            string
		serverNameHasPlaceholder bool
		expectDialTLSContext     bool
	}{
		{
			name:                 "no TLS, no proxy protocol",
			tls:                  nil,
			proxyProtocol:        "",
			expectDialTLSContext: false,
		},
		{
			name:                 "TLS without proxy protocol",
			tls:                  &TLSConfig{},
			proxyProtocol:        "",
			expectDialTLSContext: false,
		},
		{
			name:                 "TLS with proxy protocol v1",
			tls:                  &TLSConfig{},
			proxyProtocol:        "v1",
			expectDialTLSContext: true,
		},
		{
			name:                 "TLS with proxy protocol v2",
			tls:                  &TLSConfig{},
			proxyProtocol:        "v2",
			expectDialTLSContext: true,
		},
		{
			name:                     "TLS with placeholder ServerName",
			tls:                      &TLSConfig{ServerName: "{http.request.host}"},
			proxyProtocol:            "",
			serverNameHasPlaceholder: true,
			expectDialTLSContext:     true,
		},
		{
			name:                     "TLS with placeholder ServerName and proxy protocol",
			tls:                      &TLSConfig{ServerName: "{http.request.host}"},
			proxyProtocol:            "v2",
			serverNameHasPlaceholder: true,
			expectDialTLSContext:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ht := &HTTPTransport{
				TLS:           tt.tls,
				ProxyProtocol: tt.proxyProtocol,
			}

			rt, err := ht.NewTransport(ctx)
			if err != nil {
				t.Fatalf("NewTransport() error = %v", err)
			}

			hasDialTLSContext := rt.DialTLSContext != nil
			if hasDialTLSContext != tt.expectDialTLSContext {
				t.Errorf("DialTLSContext set = %v, want %v", hasDialTLSContext, tt.expectDialTLSContext)
			}
		})
	}
}

// TestHTTPTransportTLSPlaceholderThroughHTTPProxy covers CONNECT's separate TLS path.
func TestHTTPTransportTLSPlaceholderThroughHTTPProxy(t *testing.T) {
	const (
		responseBody = "hello from TLS upstream"
		serverName   = "example.com"
	)

	for _, tc := range []struct {
		name           string
		tlsServerName  string
		proxyScheme    string
		versions       []string
		wantProtoMajor int
	}{
		{"fixed server name without proxy", serverName, "", []string{"1.1"}, 1},
		{"placeholder server name without proxy", "{http.request.host}", "", []string{"1.1"}, 1},
		{"fixed server name through HTTP proxy", serverName, "http", []string{"1.1"}, 1},
		{"placeholder server name through HTTP proxy", "{http.request.host}", "http", []string{"1.1"}, 1},
		{"placeholder server name through HTTPS proxy", "{http.request.host}", "https", []string{"1.1"}, 1},
		{"placeholder server name through proxy with HTTP2", "{http.request.host}", "http", []string{"1.1", "2"}, 2},
		{"placeholder server name through proxy with h2c enabled", "{http.request.host}", "http", []string{"h2c"}, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			serverNames := make(chan string, 1)
			upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, responseBody)
			}))
			upstream.EnableHTTP2 = true
			upstream.TLS = &tls.Config{
				MinVersion: tls.VersionTLS12,
				GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
					select {
					case serverNames <- hello.ServerName:
					default:
					}
					return nil, nil
				},
			}
			upstream.StartTLS()
			t.Cleanup(upstream.Close)

			var connectProxy *testHTTPConnectProxy
			var proxyURL string
			var proxyRoots []*x509.Certificate
			if tc.proxyScheme != "" {
				connectProxy = newTestHTTPConnectProxy(t, tc.proxyScheme == "https")
				proxyURL = connectProxy.url
				if connectProxy.certificate != nil {
					proxyRoots = append(proxyRoots, connectProxy.certificate)
				}
			}
			h := newDynamicSNITestTransport(t, upstream, tc.tlsServerName, proxyURL, tc.versions, 0, proxyRoots...)
			rt := h.Transport
			var proxySelections atomic.Int32
			baseProxy := rt.Proxy
			rt.Proxy = func(req *http.Request) (*url.URL, error) {
				if _, cached := req.Context().Value(proxyLookupCtxKey{}).(proxyLookupResult); !cached {
					proxySelections.Add(1)
				}
				return baseProxy(req)
			}
			reqCtx, reqCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer reqCancel()
			req := newDynamicSNITestRequest(t, reqCtx, upstream.URL, serverName)

			resp, err := h.RoundTrip(req)
			if err != nil {
				t.Fatalf("RoundTrip: %v", err)
			}
			select {
			case gotServerName := <-serverNames:
				if gotServerName != serverName {
					t.Errorf("TLS server name = %q, want %q", gotServerName, serverName)
				}
			case <-req.Context().Done():
				t.Fatalf("TLS upstream did not receive a ClientHello: %v", req.Context().Err())
			}
			if connectProxy != nil {
				select {
				case target := <-connectProxy.connectTargets:
					if target != req.URL.Host {
						t.Fatalf("CONNECT target = %q, want %q", target, req.URL.Host)
					}
				default:
					t.Fatal("proxy did not receive a CONNECT request")
				}
			}
			if tc.proxyScheme == "https" {
				select {
				case gotServerName := <-connectProxy.serverNames:
					if gotServerName != "" {
						t.Errorf("HTTPS proxy TLS server name = %q, want empty for IP proxy host", gotServerName)
					}
				default:
					t.Fatal("HTTPS proxy did not receive a TLS ClientHello")
				}
			}
			defer resp.Body.Close()
			if resp.ProtoMajor != tc.wantProtoMajor {
				t.Errorf("response protocol = %s, want HTTP/%d", resp.Proto, tc.wantProtoMajor)
			}

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("read response body: %v", err)
			}
			if got := string(body); got != responseBody {
				t.Fatalf("response body = %q, want %q", got, responseBody)
			}
			if got := proxySelections.Load(); got != 1 {
				t.Fatalf("proxy selections = %d, want 1", got)
			}
		})
	}
}

func TestHTTPTransportDynamicSNIMaxConnsPerHost(t *testing.T) {
	const serverName = "example.com"

	requestEntered := make(chan int, 2)
	var requestCount atomic.Int32
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestNumber := int(requestCount.Add(1))
		requestEntered <- requestNumber
		if requestNumber == 1 {
			w.Header().Set("Content-Length", "100")
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			return
		}
		_, _ = io.WriteString(w, "second response")
	}))
	upstream.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
	upstream.StartTLS()
	t.Cleanup(upstream.Close)

	connectProxy := newTestHTTPConnectProxy(t, false)
	h := newDynamicSNITestTransport(t, upstream, "{http.request.host}", connectProxy.url, []string{"1.1"}, 1)
	dialFailure := errors.New("test dial failure")
	baseDialContext := h.Transport.DialContext
	var failNextDial atomic.Bool
	failNextDial.Store(true)
	h.Transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if failNextDial.CompareAndSwap(true, false) {
			return nil, dialFailure
		}
		return baseDialContext(ctx, network, addr)
	}

	type roundTripResult struct {
		resp   *http.Response
		err    error
		cancel context.CancelFunc
	}
	results := make(chan roundTripResult, 2)
	startRequest := func(host string) {
		reqCtx, reqCancel := context.WithTimeout(context.Background(), 5*time.Second)
		req := newDynamicSNITestRequest(t, reqCtx, upstream.URL, host)
		resp, err := h.RoundTrip(req)
		results <- roundTripResult{resp: resp, err: err, cancel: reqCancel}
	}
	nextResult := func(label string) roundTripResult {
		t.Helper()
		select {
		case result := <-results:
			return result
		case <-time.After(5 * time.Second):
			t.Fatalf("%s RoundTrip did not return", label)
			return roundTripResult{}
		}
	}
	checkFailedResult := func(label string, result roundTripResult) {
		t.Helper()
		if result.cancel != nil {
			result.cancel()
		}
		if result.resp != nil {
			_ = result.resp.Body.Close()
		}
		if result.err == nil {
			t.Fatalf("%s unexpectedly succeeded", label)
		}
	}

	go startRequest(serverName)
	dialResult := nextResult("dial failure")
	checkFailedResult("dial failure", dialResult)
	if !errors.Is(dialResult.err, dialFailure) {
		t.Fatalf("dial error = %v, want %v", dialResult.err, dialFailure)
	}
	go startRequest("wrong.example")
	failedResult := nextResult("invalid TLS server name")
	checkFailedResult("invalid TLS server name", failedResult)

	go startRequest(serverName)
	select {
	case requestNumber := <-requestEntered:
		if requestNumber != 1 {
			t.Fatalf("first request number = %d, want 1", requestNumber)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("first request did not reach upstream")
	}
	firstResult := nextResult("first")
	if firstResult.err != nil {
		t.Fatalf("first RoundTrip: %v", firstResult.err)
	}
	defer firstResult.cancel()
	defer firstResult.resp.Body.Close()

	go startRequest(serverName)
	waitDeadline := time.Now().Add(5 * time.Second)
	for {
		h.dynamicTLSConnLimiter.mu.Lock()
		waiting := false
		for _, entry := range h.dynamicTLSConnLimiter.entries {
			if entry.refs == 2 {
				waiting = true
				break
			}
		}
		h.dynamicTLSConnLimiter.mu.Unlock()
		if waiting {
			break
		}
		if time.Now().After(waitDeadline) {
			_ = firstResult.resp.Body.Close()
			t.Fatal("second request did not wait for a connection permit")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case requestNumber := <-requestEntered:
		_ = firstResult.resp.Body.Close()
		t.Fatalf("request %d reached upstream while the first connection was still active", requestNumber)
	default:
	}

	if err := firstResult.resp.Body.Close(); err != nil {
		t.Fatalf("close first response body: %v", err)
	}
	select {
	case requestNumber := <-requestEntered:
		if requestNumber != 2 {
			t.Fatalf("second request number = %d, want 2", requestNumber)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("second request remained blocked after the first connection closed")
	}
	secondResult := nextResult("second")
	if secondResult.cancel != nil {
		defer secondResult.cancel()
	}
	if secondResult.err != nil {
		t.Fatalf("second RoundTrip: %v", secondResult.err)
	}
	defer secondResult.resp.Body.Close()
	body, err := io.ReadAll(secondResult.resp.Body)
	if err != nil {
		t.Fatalf("read second response: %v", err)
	}
	if got := string(body); got != "second response" {
		t.Fatalf("second response body = %q, want %q", got, "second response")
	}
}

func TestHTTPTransportDynamicSNIDirectConnectionReuse(t *testing.T) {
	const serverName = "example.com"

	var handshakes atomic.Int32
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	upstream.TLS = &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			handshakes.Add(1)
			return nil, nil
		},
	}
	upstream.StartTLS()
	t.Cleanup(upstream.Close)

	h := newDynamicSNITestTransport(t, upstream, "{http.request.host}", "", []string{"1.1"}, 0)

	for i := 0; i < 2; i++ {
		req := newDynamicSNITestRequest(t, context.Background(), upstream.URL, serverName)
		resp, err := h.RoundTrip(req)
		if err != nil {
			t.Fatalf("RoundTrip %d: %v", i, err)
		}
		if _, err := io.Copy(io.Discard, resp.Body); err != nil {
			_ = resp.Body.Close()
			t.Fatalf("read response %d: %v", i, err)
		}
		if err := resp.Body.Close(); err != nil {
			t.Fatalf("close response %d: %v", i, err)
		}
	}

	if got := handshakes.Load(); got != 1 {
		t.Fatalf("TLS handshakes = %d, want 1 reused connection", got)
	}
}

func TestHTTPTransportDynamicSNIProxyConnectionReuse(t *testing.T) {
	const serverName = "example.com"

	for _, tc := range []struct {
		name     string
		proxyTLS bool
	}{
		{"HTTP proxy", false},
		{"HTTPS proxy", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var upstreamHandshakes atomic.Int32
			upstreamServerNames := make(chan string, 2)
			upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, "ok")
			}))
			upstream.TLS = &tls.Config{
				MinVersion: tls.VersionTLS12,
				GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
					upstreamHandshakes.Add(1)
					upstreamServerNames <- hello.ServerName
					return nil, nil
				},
			}
			upstream.StartTLS()
			t.Cleanup(upstream.Close)

			connectProxy := newTestHTTPConnectProxy(t, tc.proxyTLS)
			var proxyRoots []*x509.Certificate
			if connectProxy.certificate != nil {
				proxyRoots = append(proxyRoots, connectProxy.certificate)
			}
			h := newDynamicSNITestTransport(t, upstream, "{http.request.host}", connectProxy.url, []string{"1.1"}, 0, proxyRoots...)

			roundTrip := func(requestNumber int, requestServerName string) {
				t.Helper()
				req := newDynamicSNITestRequest(t, context.Background(), upstream.URL, requestServerName)
				resp, err := h.RoundTrip(req)
				if err != nil {
					t.Fatalf("RoundTrip %d: %v", requestNumber, err)
				}
				if _, err := io.Copy(io.Discard, resp.Body); err != nil {
					_ = resp.Body.Close()
					t.Fatalf("read response %d: %v", requestNumber, err)
				}
				if err := resp.Body.Close(); err != nil {
					t.Fatalf("close response %d: %v", requestNumber, err)
				}
			}
			for i := 0; i < 2; i++ {
				roundTrip(i, serverName)
			}

			if got := connectProxy.connections.Load(); got != 1 {
				t.Errorf("proxy connections = %d, want 1 reused connection", got)
			}
			if got := connectProxy.connects.Load(); got != 1 {
				t.Errorf("CONNECT requests = %d, want 1 reused tunnel", got)
			}
			if got := upstreamHandshakes.Load(); got != 1 {
				t.Errorf("upstream TLS handshakes = %d, want 1 reused connection", got)
			}
			wantProxyHandshakes := int32(0)
			if tc.proxyTLS {
				wantProxyHandshakes = 1
			}
			if got := connectProxy.tlsHandshakes.Load(); got != wantProxyHandshakes {
				t.Errorf("proxy TLS handshakes = %d, want %d", got, wantProxyHandshakes)
			}
			select {
			case gotServerName := <-upstreamServerNames:
				if gotServerName != serverName {
					t.Errorf("upstream TLS server name = %q, want %q", gotServerName, serverName)
				}
			default:
				t.Fatal("upstream did not receive a TLS ClientHello")
			}

			const secondServerName = "second.example.com"
			roundTrip(2, secondServerName)
			if got := connectProxy.connections.Load(); got != 2 {
				t.Errorf("proxy connections after SNI change = %d, want 2 separate connections", got)
			}
			if got := connectProxy.connects.Load(); got != 2 {
				t.Errorf("CONNECT requests after SNI change = %d, want 2 separate tunnels", got)
			}
			if got := upstreamHandshakes.Load(); got != 2 {
				t.Errorf("upstream TLS handshakes after SNI change = %d, want 2", got)
			}
			wantProxyHandshakes *= 2
			if got := connectProxy.tlsHandshakes.Load(); got != wantProxyHandshakes {
				t.Errorf("proxy TLS handshakes after SNI change = %d, want %d", got, wantProxyHandshakes)
			}
			select {
			case gotServerName := <-upstreamServerNames:
				if gotServerName != secondServerName {
					t.Errorf("second upstream TLS server name = %q, want %q", gotServerName, secondServerName)
				}
			default:
				t.Fatal("upstream did not receive a second TLS ClientHello")
			}
		})
	}
}

func TestTransportConnLimiter(t *testing.T) {
	limiter := &transportConnLimiter{
		limit:   1,
		entries: make(map[string]*transportConnLimitEntry),
	}

	releaseA, err := limiter.acquire(context.Background(), "target-a")
	if err != nil {
		t.Fatalf("acquire target-a: %v", err)
	}
	releaseB, err := limiter.acquire(context.Background(), "target-b")
	if err != nil {
		t.Fatalf("acquire independent target-b: %v", err)
	}

	waitCtx, waitCancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer waitCancel()
	if _, err := limiter.acquire(waitCtx, "target-a"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocked acquire error = %v, want context deadline exceeded", err)
	}

	releaseA()
	releaseA()
	releaseAAgain, err := limiter.acquire(context.Background(), "target-a")
	if err != nil {
		t.Fatalf("reacquire target-a: %v", err)
	}
	releaseAAgain()
	releaseB()

	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	if len(limiter.entries) != 0 {
		t.Fatalf("limiter retained %d unused entries, want 0", len(limiter.entries))
	}
}

func TestDynamicTLSConnKey(t *testing.T) {
	proxyURL, err := url.Parse("http://proxy.example:3128")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		targetURL string
		h1Only    bool
		want      string
	}{
		{"https://BÜCHER.example/path", false, "http://proxy.example:3128\x00https\x00xn--bcher-kva.example:443"},
		{"https://Example.COM:8443", true, "http://proxy.example:3128\x00https\x00example.com:8443\x00h1"},
	} {
		req := newDynamicSNITestRequest(t, context.Background(), tc.targetURL, "example.com")
		if tc.h1Only {
			caddyhttp.SetVar(req.Context(), tlsH1OnlyVarKey, true)
		}
		if got := dynamicTLSConnKey(req, proxyURL); got != tc.want {
			t.Errorf("dynamicTLSConnKey(%q) = %q, want %q", tc.targetURL, got, tc.want)
		}
	}
}

func newDynamicSNITestTransport(
	t *testing.T,
	upstream *httptest.Server,
	tlsServerName, proxyURL string,
	versions []string,
	maxConnsPerHost int,
	extraRoots ...*x509.Certificate,
) *HTTPTransport {
	t.Helper()

	networkProxyRaw := caddyconfig.JSONModuleObject(network.ProxyFromNone{}, "from", "none", nil)
	if proxyURL != "" {
		networkProxyRaw = caddyconfig.JSONModuleObject(network.ProxyFromURL{URL: proxyURL}, "from", "url", nil)
	}
	h := &HTTPTransport{
		TLS:             &TLSConfig{ServerName: tlsServerName},
		NetworkProxyRaw: networkProxyRaw,
		Versions:        versions,
		MaxConnsPerHost: maxConnsPerHost,
	}
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	t.Cleanup(cancel)
	rt, err := h.NewTransport(ctx)
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(upstream.Certificate())
	for _, cert := range extraRoots {
		roots.AddCert(cert)
	}
	rt.TLSClientConfig.RootCAs = roots
	h.Transport = rt
	t.Cleanup(func() {
		if err := h.Cleanup(); err != nil {
			t.Errorf("cleanup HTTP transport: %v", err)
		}
	})
	return h
}

func newDynamicSNITestRequest(t *testing.T, ctx context.Context, targetURL, host string) *http.Request {
	t.Helper()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Host = host
	return caddyhttp.PrepareRequest(req, caddy.NewReplacer(), nil, &caddyhttp.Server{})
}

type testHTTPConnectProxy struct {
	url            string
	certificate    *x509.Certificate
	connectTargets <-chan string
	serverNames    <-chan string
	connections    atomic.Int32
	connects       atomic.Int32
	tlsHandshakes  atomic.Int32
}

func newTestHTTPConnectProxy(t *testing.T, useTLS bool) *testHTTPConnectProxy {
	t.Helper()

	connectTargets := make(chan string, 10)
	serverNames := make(chan string, 10)
	result := &testHTTPConnectProxy{
		connectTargets: connectTargets,
		serverNames:    serverNames,
	}
	proxy := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT required", http.StatusMethodNotAllowed)
			return
		}

		upstreamConn, err := net.DialTimeout("tcp", r.Host, 5*time.Second)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer upstreamConn.Close()

		hijacker, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijacking not supported", http.StatusInternalServerError)
			return
		}
		clientConn, clientReadWriter, err := hijacker.Hijack()
		if err != nil {
			return
		}
		defer clientConn.Close()

		result.connects.Add(1)
		connectTargets <- r.Host
		if _, err := clientReadWriter.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			return
		}
		if err := clientReadWriter.Flush(); err != nil {
			return
		}

		copyDone := make(chan struct{}, 2)
		go func() {
			_, _ = io.Copy(upstreamConn, clientReadWriter)
			copyDone <- struct{}{}
		}()
		go func() {
			_, _ = io.Copy(clientConn, upstreamConn)
			copyDone <- struct{}{}
		}()
		<-copyDone
	}))
	proxy.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			result.connections.Add(1)
		}
	}
	if useTLS {
		proxy.TLS = &tls.Config{
			MinVersion: tls.VersionTLS12,
			GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
				result.tlsHandshakes.Add(1)
				serverNames <- hello.ServerName
				return nil, nil
			},
		}
		proxy.StartTLS()
		result.certificate = proxy.Certificate()
	} else {
		proxy.Start()
	}
	t.Cleanup(proxy.Close)

	result.url = proxy.URL
	return result
}

func TestHTTPTransport_DialContext_ProxyProtocolClosesConnectionOnError(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	validAddrPort := netip.MustParseAddrPort("192.0.2.1:1234")
	tests := []struct {
		name      string
		version   string
		proxyInfo *ProxyProtocolInfo
	}{
		{
			name:    "missing proxy protocol info",
			version: "v1",
		},
		{
			name:      "unexpected proxy protocol version",
			version:   "v3",
			proxyInfo: &ProxyProtocolInfo{AddrPort: validAddrPort},
		},
		{
			name:      "unexpected remote address type",
			version:   "v1",
			proxyInfo: &ProxyProtocolInfo{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			t.Cleanup(func() { listener.Close() })

			readResult := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					readResult <- err
					return
				}
				defer conn.Close()
				_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				var buf [1]byte
				_, err = conn.Read(buf[:])
				readResult <- err
			}()

			dialCtx := context.WithValue(context.Background(), caddyhttp.VarsCtxKey, make(map[string]any))
			if tt.proxyInfo != nil {
				caddyhttp.SetVar(dialCtx, proxyProtocolInfoVarKey, *tt.proxyInfo)
			}

			rt, err := (&HTTPTransport{ProxyProtocol: tt.version}).NewTransport(ctx)
			if err != nil {
				t.Fatalf("NewTransport: %v", err)
			}
			conn, err := rt.DialContext(dialCtx, "tcp", listener.Addr().String())
			if err == nil {
				conn.Close()
				t.Fatal("DialContext succeeded, want error")
			}

			if readErr := <-readResult; !errors.Is(readErr, io.EOF) {
				t.Fatalf("server read error = %v, want EOF after client connection close", readErr)
			}
		})
	}
}

// TestHTTPTransport_DialContext_DialInfoOverride is a regression test for
// issue #6447: a `tcp4/`-prefixed upstream silently fell back to plain `tcp`
// because dialContext only honored DialInfo for unix networks. PR #7300 widened
// the condition so DialInfo is honored when no upstream HTTP proxy is in use,
// and skipped (for non-unix networks) when one is. Both halves are pinned here.
func TestHTTPTransport_DialContext_DialInfoOverride(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	ht := &HTTPTransport{}
	rt, err := ht.NewTransport(ctx)
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}

	proxyURL, err := url.Parse("http://proxy.example:8080")
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}

	tests := []struct {
		name        string
		proxy       bool
		dialInfo    string
		defaultAddr string
	}{
		{
			// no proxy: DialInfo should be applied, so the dial lands on
			// the live listener despite the bogus default address.
			name:        "honors DialInfo when no proxy",
			proxy:       false,
			dialInfo:    ln.Addr().String(),
			defaultAddr: "127.0.0.1:1",
		},
		{
			// proxy active: DialInfo must NOT be applied for non-unix
			// networks; the default address (the live listener) is used.
			name:        "skips DialInfo when proxy active",
			proxy:       true,
			dialInfo:    "127.0.0.1:1",
			defaultAddr: ln.Addr().String(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dialCtx := context.WithValue(context.Background(), caddyhttp.VarsCtxKey, make(map[string]any))
			dialCtx = context.WithValue(dialCtx, dialInfoCtxKey, DialInfo{
				Network: "tcp4",
				Address: tt.dialInfo,
			})
			if tt.proxy {
				caddyhttp.SetVar(dialCtx, proxyVarKey, proxyURL)
			}

			conn, err := rt.DialContext(dialCtx, "tcp", tt.defaultAddr)
			if err != nil {
				t.Fatalf("DialContext: %v", err)
			}
			t.Cleanup(func() { conn.Close() })
			if got := conn.RemoteAddr().String(); got != ln.Addr().String() {
				t.Fatalf("conn.RemoteAddr() = %s, want %s", got, ln.Addr().String())
			}
		})
	}
}
