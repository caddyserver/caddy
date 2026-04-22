package caddyhttp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type writeFunc func(p []byte) (int, error)

type nopSyncer writeFunc

func (n nopSyncer) Write(p []byte) (int, error) {
	return n(p)
}

func (n nopSyncer) Sync() error {
	return nil
}

// testLogger returns a logger and a buffer to which the logger writes. The
// buffer can be read for asserting log output.
func testLogger(wf writeFunc) *zap.Logger {
	ws := nopSyncer(wf)
	encoderCfg := zapcore.EncoderConfig{
		MessageKey:     "msg",
		LevelKey:       "level",
		NameKey:        "logger",
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.StringDurationEncoder,
	}
	core := zapcore.NewCore(zapcore.NewJSONEncoder(encoderCfg), ws, zap.DebugLevel)

	return zap.New(core)
}

func TestServer_LogRequest(t *testing.T) {
	s := &Server{}

	ctx := context.Background()
	ctx = context.WithValue(ctx, ExtraLogFieldsCtxKey, new(ExtraLogFields))
	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	wrec := NewResponseRecorder(rec, nil, nil)

	duration := 50 * time.Millisecond
	repl := NewTestReplacer(req)
	bodyReader := &lengthReader{Source: req.Body}
	shouldLogCredentials := false

	buf := bytes.Buffer{}
	accLog := testLogger(buf.Write)
	s.logRequest(accLog, req, wrec, &duration, repl, bodyReader, shouldLogCredentials)

	assert.JSONEq(t, `{
		"msg":"handled request", "level":"info", "bytes_read":0,
		"duration":"50ms", "resp_headers": {}, "size":0,
		"status":0, "user_id":""
	}`, buf.String())
}

func TestServer_LogRequest_WithTrace(t *testing.T) {
	s := &Server{}

	extra := new(ExtraLogFields)
	ctx := context.WithValue(context.Background(), ExtraLogFieldsCtxKey, extra)
	extra.Add(zap.String("traceID", "1234567890abcdef"))
	extra.Add(zap.String("spanID", "12345678"))

	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	wrec := NewResponseRecorder(rec, nil, nil)

	duration := 50 * time.Millisecond
	repl := NewTestReplacer(req)
	bodyReader := &lengthReader{Source: req.Body}
	shouldLogCredentials := false

	buf := bytes.Buffer{}
	accLog := testLogger(buf.Write)
	s.logRequest(accLog, req, wrec, &duration, repl, bodyReader, shouldLogCredentials)

	assert.JSONEq(t, `{
		"msg":"handled request", "level":"info", "bytes_read":0,
		"duration":"50ms", "resp_headers": {}, "size":0,
		"status":0, "user_id":"",
		"traceID":"1234567890abcdef",
		"spanID":"12345678"
	}`, buf.String())
}

func BenchmarkServer_LogRequest(b *testing.B) {
	s := &Server{}

	extra := new(ExtraLogFields)
	ctx := context.WithValue(context.Background(), ExtraLogFieldsCtxKey, extra)

	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	wrec := NewResponseRecorder(rec, nil, nil)

	duration := 50 * time.Millisecond
	repl := NewTestReplacer(req)
	bodyReader := &lengthReader{Source: req.Body}

	buf := io.Discard
	accLog := testLogger(buf.Write)

	for b.Loop() {
		s.logRequest(accLog, req, wrec, &duration, repl, bodyReader, false)
	}
}

func BenchmarkServer_LogRequest_NopLogger(b *testing.B) {
	s := &Server{}

	extra := new(ExtraLogFields)
	ctx := context.WithValue(context.Background(), ExtraLogFieldsCtxKey, extra)

	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	wrec := NewResponseRecorder(rec, nil, nil)

	duration := 50 * time.Millisecond
	repl := NewTestReplacer(req)
	bodyReader := &lengthReader{Source: req.Body}

	accLog := zap.NewNop()

	for b.Loop() {
		s.logRequest(accLog, req, wrec, &duration, repl, bodyReader, false)
	}
}

func BenchmarkServer_LogRequest_WithTrace(b *testing.B) {
	s := &Server{}

	extra := new(ExtraLogFields)
	ctx := context.WithValue(context.Background(), ExtraLogFieldsCtxKey, extra)
	extra.Add(zap.String("traceID", "1234567890abcdef"))
	extra.Add(zap.String("spanID", "12345678"))

	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	wrec := NewResponseRecorder(rec, nil, nil)

	duration := 50 * time.Millisecond
	repl := NewTestReplacer(req)
	bodyReader := &lengthReader{Source: req.Body}

	buf := io.Discard
	accLog := testLogger(buf.Write)

	for b.Loop() {
		s.logRequest(accLog, req, wrec, &duration, repl, bodyReader, false)
	}
}

func TestServer_TrustedRealClientIP_NoTrustedHeaders(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.0.2.1:12345"
	ip := trustedRealClientIP(req, []string{}, "192.0.2.1")

	assert.Equal(t, ip, "192.0.2.1")
}

func TestServer_TrustedRealClientIP_OneTrustedHeaderEmpty(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.0.2.1:12345"
	ip := trustedRealClientIP(req, []string{"X-Forwarded-For"}, "192.0.2.1")

	assert.Equal(t, ip, "192.0.2.1")
}

func TestServer_TrustedRealClientIP_OneTrustedHeaderInvalid(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.0.2.1:12345"
	req.Header.Set("X-Forwarded-For", "not, an, ip")
	ip := trustedRealClientIP(req, []string{"X-Forwarded-For"}, "192.0.2.1")

	assert.Equal(t, ip, "192.0.2.1")
}

func TestServer_TrustedRealClientIP_OneTrustedHeaderValid(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.0.2.1:12345"
	req.Header.Set("X-Forwarded-For", "10.0.0.1")
	ip := trustedRealClientIP(req, []string{"X-Forwarded-For"}, "192.0.2.1")

	assert.Equal(t, ip, "10.0.0.1")
}

func TestServer_TrustedRealClientIP_OneTrustedHeaderValidArray(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.0.2.1:12345"
	req.Header.Set("X-Forwarded-For", "1.1.1.1, 2.2.2.2, 3.3.3.3")
	ip := trustedRealClientIP(req, []string{"X-Forwarded-For"}, "192.0.2.1")

	assert.Equal(t, ip, "1.1.1.1")
}

func TestServer_TrustedRealClientIP_IncludesPort(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.0.2.1:12345"
	req.Header.Set("X-Forwarded-For", "1.1.1.1:1234")
	ip := trustedRealClientIP(req, []string{"X-Forwarded-For"}, "192.0.2.1")

	assert.Equal(t, ip, "1.1.1.1")
}

func TestServer_TrustedRealClientIP_SkipsInvalidIps(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.0.2.1:12345"
	req.Header.Set("X-Forwarded-For", "not an ip, bad bad, 10.0.0.1")
	ip := trustedRealClientIP(req, []string{"X-Forwarded-For"}, "192.0.2.1")

	assert.Equal(t, ip, "10.0.0.1")
}

func TestServer_TrustedRealClientIP_MultipleTrustedHeaderValidArray(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.0.2.1:12345"
	req.Header.Set("Real-Client-IP", "1.1.1.1, 2.2.2.2, 3.3.3.3")
	req.Header.Set("X-Forwarded-For", "3.3.3.3, 4.4.4.4")
	ip1 := trustedRealClientIP(req, []string{"X-Forwarded-For", "Real-Client-IP"}, "192.0.2.1")
	ip2 := trustedRealClientIP(req, []string{"Real-Client-IP", "X-Forwarded-For"}, "192.0.2.1")
	ip3 := trustedRealClientIP(req, []string{"Missing-Header-IP", "Real-Client-IP", "X-Forwarded-For"}, "192.0.2.1")

	assert.Equal(t, ip1, "3.3.3.3")
	assert.Equal(t, ip2, "1.1.1.1")
	assert.Equal(t, ip3, "1.1.1.1")
}

func TestServer_DetermineTrustedProxy_NoConfig(t *testing.T) {
	server := &Server{}

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.0.2.1:12345"

	trusted, clientIP := determineTrustedProxy(req, server)

	assert.False(t, trusted)
	assert.Equal(t, clientIP, "192.0.2.1")
}

func TestServer_DetermineTrustedProxy_NoConfigIpv6(t *testing.T) {
	server := &Server{}

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "[::1]:12345"

	trusted, clientIP := determineTrustedProxy(req, server)

	assert.False(t, trusted)
	assert.Equal(t, clientIP, "::1")
}

func TestServer_DetermineTrustedProxy_NoConfigIpv6Zones(t *testing.T) {
	server := &Server{}

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "[::1%eth2]:12345"

	trusted, clientIP := determineTrustedProxy(req, server)

	assert.False(t, trusted)
	assert.Equal(t, clientIP, "::1")
}

func TestServer_DetermineTrustedProxy_TrustedLoopback(t *testing.T) {
	loopbackPrefix, _ := netip.ParsePrefix("127.0.0.1/8")

	server := &Server{
		trustedProxies: &StaticIPRange{
			ranges: []netip.Prefix{loopbackPrefix},
		},
		ClientIPHeaders: []string{"X-Forwarded-For"},
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "31.40.0.10")

	trusted, clientIP := determineTrustedProxy(req, server)

	assert.True(t, trusted)
	assert.Equal(t, clientIP, "31.40.0.10")
}

func TestServer_DetermineTrustedProxy_UnixSocket(t *testing.T) {
	server := &Server{
		ClientIPHeaders:    []string{"X-Forwarded-For"},
		TrustedProxiesUnix: true,
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "@"
	req.Header.Set("X-Forwarded-For", "2.2.2.2, 3.3.3.3")

	trusted, clientIP := determineTrustedProxy(req, server)

	assert.True(t, trusted)
	assert.Equal(t, "2.2.2.2", clientIP)
}

func TestServer_DetermineTrustedProxy_UnixSocketStrict(t *testing.T) {
	server := &Server{
		ClientIPHeaders:      []string{"X-Forwarded-For"},
		TrustedProxiesUnix:   true,
		TrustedProxiesStrict: 1,
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "@"
	req.Header.Set("X-Forwarded-For", "2.2.2.2, 3.3.3.3")

	trusted, clientIP := determineTrustedProxy(req, server)

	assert.True(t, trusted)
	assert.Equal(t, "3.3.3.3", clientIP)
}

func TestServer_DetermineTrustedProxy_UntrustedPrefix(t *testing.T) {
	loopbackPrefix, _ := netip.ParsePrefix("127.0.0.1/8")

	server := &Server{
		trustedProxies: &StaticIPRange{
			ranges: []netip.Prefix{loopbackPrefix},
		},
		ClientIPHeaders: []string{"X-Forwarded-For"},
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "31.40.0.10")

	trusted, clientIP := determineTrustedProxy(req, server)

	assert.False(t, trusted)
	assert.Equal(t, clientIP, "10.0.0.1")
}

func TestServer_DetermineTrustedProxy_MultipleTrustedPrefixes(t *testing.T) {
	loopbackPrefix, _ := netip.ParsePrefix("127.0.0.1/8")
	localPrivatePrefix, _ := netip.ParsePrefix("10.0.0.0/8")

	server := &Server{
		trustedProxies: &StaticIPRange{
			ranges: []netip.Prefix{loopbackPrefix, localPrivatePrefix},
		},
		ClientIPHeaders: []string{"X-Forwarded-For"},
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "31.40.0.10")

	trusted, clientIP := determineTrustedProxy(req, server)

	assert.True(t, trusted)
	assert.Equal(t, clientIP, "31.40.0.10")
}

func TestServer_DetermineTrustedProxy_MultipleTrustedClientHeaders(t *testing.T) {
	loopbackPrefix, _ := netip.ParsePrefix("127.0.0.1/8")
	localPrivatePrefix, _ := netip.ParsePrefix("10.0.0.0/8")

	server := &Server{
		trustedProxies: &StaticIPRange{
			ranges: []netip.Prefix{loopbackPrefix, localPrivatePrefix},
		},
		ClientIPHeaders: []string{"CF-Connecting-IP", "X-Forwarded-For"},
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header.Set("CF-Connecting-IP", "1.1.1.1, 2.2.2.2")
	req.Header.Set("X-Forwarded-For", "3.3.3.3, 4.4.4.4")

	trusted, clientIP := determineTrustedProxy(req, server)

	assert.True(t, trusted)
	assert.Equal(t, clientIP, "1.1.1.1")
}

func TestServer_DetermineTrustedProxy_MatchLeftMostValidIp(t *testing.T) {
	localPrivatePrefix, _ := netip.ParsePrefix("10.0.0.0/8")

	server := &Server{
		trustedProxies: &StaticIPRange{
			ranges: []netip.Prefix{localPrivatePrefix},
		},
		ClientIPHeaders: []string{"X-Forwarded-For"},
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "30.30.30.30, 45.54.45.54, 10.0.0.1")

	trusted, clientIP := determineTrustedProxy(req, server)

	assert.True(t, trusted)
	assert.Equal(t, clientIP, "30.30.30.30")
}

func TestServer_DetermineTrustedProxy_MatchRightMostUntrusted(t *testing.T) {
	localPrivatePrefix, _ := netip.ParsePrefix("10.0.0.0/8")

	server := &Server{
		trustedProxies: &StaticIPRange{
			ranges: []netip.Prefix{localPrivatePrefix},
		},
		ClientIPHeaders:      []string{"X-Forwarded-For"},
		TrustedProxiesStrict: 1,
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "30.30.30.30, 45.54.45.54, 10.0.0.1")

	trusted, clientIP := determineTrustedProxy(req, server)

	assert.True(t, trusted)
	assert.Equal(t, clientIP, "45.54.45.54")
}

func TestServer_DetermineTrustedProxy_MatchRightMostUntrustedSkippingEmpty(t *testing.T) {
	localPrivatePrefix, _ := netip.ParsePrefix("10.0.0.0/8")

	server := &Server{
		trustedProxies: &StaticIPRange{
			ranges: []netip.Prefix{localPrivatePrefix},
		},
		ClientIPHeaders:      []string{"Missing-Header", "CF-Connecting-IP", "X-Forwarded-For"},
		TrustedProxiesStrict: 1,
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header.Set("CF-Connecting-IP", "not a real IP")
	req.Header.Set("X-Forwarded-For", "30.30.30.30, bad, 45.54.45.54, not real")

	trusted, clientIP := determineTrustedProxy(req, server)

	assert.True(t, trusted)
	assert.Equal(t, clientIP, "45.54.45.54")
}

func TestServer_DetermineTrustedProxy_MatchRightMostUntrustedSkippingTrusted(t *testing.T) {
	localPrivatePrefix, _ := netip.ParsePrefix("10.0.0.0/8")

	server := &Server{
		trustedProxies: &StaticIPRange{
			ranges: []netip.Prefix{localPrivatePrefix},
		},
		ClientIPHeaders:      []string{"CF-Connecting-IP", "X-Forwarded-For"},
		TrustedProxiesStrict: 1,
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header.Set("CF-Connecting-IP", "10.0.0.1, 10.0.0.2, 10.0.0.3")
	req.Header.Set("X-Forwarded-For", "30.30.30.30, 45.54.45.54, 10.0.0.4")

	trusted, clientIP := determineTrustedProxy(req, server)

	assert.True(t, trusted)
	assert.Equal(t, clientIP, "45.54.45.54")
}

// TestServer_serveHTTP_DropsUnderscoreHeader covers GHSA-f59h-q822-g45g: an
// underscore-named alias (e.g. `Remote_user`) of a hyphenated header must be
// dropped before any handler runs.
func TestServer_serveHTTP_DropsUnderscoreHeader(t *testing.T) {
	got := &http.Header{}
	s := &Server{
		logger: zap.NewNop(),
		primaryHandlerChain: HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			*got = r.Header.Clone()
			return nil
		}),
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header["X-Real-Header"] = []string{"ok"}
	req.Header["Remote_user"] = []string{"attacker"}
	req.Header["Remote_groups"] = []string{"admin"}

	require.NoError(t, s.serveHTTP(httptest.NewRecorder(), req))
	assert.NotContains(t, *got, "Remote_user")
	assert.NotContains(t, *got, "Remote_groups")
	assert.Equal(t, "ok", got.Get("X-Real-Header"))
}

// TestServer_serveHTTP_LogsDroppedUnderscoreHeader verifies each dropped
// header is emitted at debug level so operators can diagnose unexpectedly
// missing headers without spamming the log on adversarial traffic.
func TestServer_serveHTTP_LogsDroppedUnderscoreHeader(t *testing.T) {
	var buf bytes.Buffer
	s := &Server{
		logger: testLogger(buf.Write),
		primaryHandlerChain: HandlerFunc(func(http.ResponseWriter, *http.Request) error {
			return nil
		}),
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header["Remote_user"] = []string{"attacker"}

	require.NoError(t, s.serveHTTP(httptest.NewRecorder(), req))
	assert.Contains(t, buf.String(), `"level":"debug"`)
	assert.Contains(t, buf.String(), `"msg":"dropping header containing underscore"`)
	assert.Contains(t, buf.String(), `"header":"Remote_user"`)
}

// --- Allowlist: exact match ---

func TestServer_serveHTTP_AllowlistKeepsExactMatch(t *testing.T) {
	got := &http.Header{}
	s := &Server{
		logger:                    zap.NewNop(),
		ExpectedUnderscoreHeaders: []string{"user_id"},
		primaryHandlerChain: HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			*got = r.Header.Clone()
			return nil
		}),
	}
	require.NoError(t, s.provisionUnderscoreHeaders())

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header["User_id"] = []string{"zeus"}

	require.NoError(t, s.serveHTTP(httptest.NewRecorder(), req))
	assert.Equal(t, "zeus", got.Get("User_id"))
}

func TestServer_serveHTTP_AllowlistDropsHyphenatedVariant(t *testing.T) {
	got := &http.Header{}
	s := &Server{
		logger:                    zap.NewNop(),
		ExpectedUnderscoreHeaders: []string{"user_id"},
		primaryHandlerChain: HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			*got = r.Header.Clone()
			return nil
		}),
	}
	require.NoError(t, s.provisionUnderscoreHeaders())

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header["User_id"] = []string{"zeus"}
	req.Header.Set("User-Id", "attacker")

	require.NoError(t, s.serveHTTP(httptest.NewRecorder(), req))
	assert.Equal(t, "zeus", got.Get("User_id"))
	assert.NotContains(t, *got, "User-Id")
}

func TestServer_serveHTTP_AllowlistDropsUnlisted(t *testing.T) {
	got := &http.Header{}
	s := &Server{
		logger:                    zap.NewNop(),
		ExpectedUnderscoreHeaders: []string{"user_id"},
		primaryHandlerChain: HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			*got = r.Header.Clone()
			return nil
		}),
	}
	require.NoError(t, s.provisionUnderscoreHeaders())

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header["User_id"] = []string{"zeus"}
	req.Header["Remote_user"] = []string{"attacker"}

	require.NoError(t, s.serveHTTP(httptest.NewRecorder(), req))
	assert.Equal(t, "zeus", got.Get("User_id"))
	assert.NotContains(t, *got, "Remote_user")
}

func TestServer_serveHTTP_AllowlistPassesThroughNormalHeaders(t *testing.T) {
	got := &http.Header{}
	s := &Server{
		logger:                    zap.NewNop(),
		ExpectedUnderscoreHeaders: []string{"user_id"},
		primaryHandlerChain: HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			*got = r.Header.Clone()
			return nil
		}),
	}
	require.NoError(t, s.provisionUnderscoreHeaders())

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set("X-Real-Header", "ok")
	req.Header.Set("Content-Type", "text/plain")

	require.NoError(t, s.serveHTTP(httptest.NewRecorder(), req))
	assert.Equal(t, "ok", got.Get("X-Real-Header"))
	assert.Equal(t, "text/plain", got.Get("Content-Type"))
}

// --- Allowlist: mixed underscore/hyphen entry ---

func TestServer_serveHTTP_MixedEntryKeepsOriginal(t *testing.T) {
	got := &http.Header{}
	s := &Server{
		logger:                    zap.NewNop(),
		ExpectedUnderscoreHeaders: []string{"__user-id"},
		primaryHandlerChain: HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			*got = r.Header.Clone()
			return nil
		}),
	}
	require.NoError(t, s.provisionUnderscoreHeaders())

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header["__user-Id"] = []string{"zeus"} // canonical form of __user-id

	require.NoError(t, s.serveHTTP(httptest.NewRecorder(), req))
	assert.Equal(t, "zeus", got.Get("__user-Id"))
}

func TestServer_serveHTTP_MixedEntryDropsFullyHyphenated(t *testing.T) {
	got := &http.Header{}
	s := &Server{
		logger:                    zap.NewNop(),
		ExpectedUnderscoreHeaders: []string{"__user-id"},
		primaryHandlerChain: HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			*got = r.Header.Clone()
			return nil
		}),
	}
	require.NoError(t, s.provisionUnderscoreHeaders())

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header["--User-Id"] = []string{"attacker"} // fully hyphenated variant

	require.NoError(t, s.serveHTTP(httptest.NewRecorder(), req))
	assert.NotContains(t, *got, "--User-Id")
}

func TestServer_serveHTTP_MixedEntryDropsPartialVariants(t *testing.T) {
	got := &http.Header{}
	s := &Server{
		logger:                    zap.NewNop(),
		ExpectedUnderscoreHeaders: []string{"__user-id"},
		primaryHandlerChain: HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			*got = r.Header.Clone()
			return nil
		}),
	}
	require.NoError(t, s.provisionUnderscoreHeaders())

	// All partial variants still contain underscores and don't match
	// the allowlist, so they are dropped by the normal underscore filter.
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header["-_user-Id"] = []string{"attacker1"} // canonical of -_user-id
	req.Header["_-User-Id"] = []string{"attacker2"} // canonical of _-user-id
	req.Header["__user_id"] = []string{"attacker3"} // all underscores variant

	require.NoError(t, s.serveHTTP(httptest.NewRecorder(), req))
	assert.NotContains(t, *got, "-_user-Id")
	assert.NotContains(t, *got, "_-User-Id")
	assert.NotContains(t, *got, "__user_id")
}

// --- Allowlist: prefix glob ---

func TestServer_serveHTTP_PrefixGlobKeepsMatch(t *testing.T) {
	got := &http.Header{}
	s := &Server{
		logger:                    zap.NewNop(),
		ExpectedUnderscoreHeaders: []string{"webhook_*"},
		primaryHandlerChain: HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			*got = r.Header.Clone()
			return nil
		}),
	}
	require.NoError(t, s.provisionUnderscoreHeaders())

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header["Webhook_event"] = []string{"push"}

	require.NoError(t, s.serveHTTP(httptest.NewRecorder(), req))
	assert.Equal(t, "push", got.Get("Webhook_event"))
}

func TestServer_serveHTTP_PrefixGlobDropsHyphenatedVariant(t *testing.T) {
	got := &http.Header{}
	s := &Server{
		logger:                    zap.NewNop(),
		ExpectedUnderscoreHeaders: []string{"webhook_*"},
		primaryHandlerChain: HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			*got = r.Header.Clone()
			return nil
		}),
	}
	require.NoError(t, s.provisionUnderscoreHeaders())

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set("Webhook-Event", "push")

	require.NoError(t, s.serveHTTP(httptest.NewRecorder(), req))
	assert.NotContains(t, *got, "Webhook-Event")
}

func TestServer_serveHTTP_PrefixGlobDropsNonMatching(t *testing.T) {
	got := &http.Header{}
	s := &Server{
		logger:                    zap.NewNop(),
		ExpectedUnderscoreHeaders: []string{"webhook_*"},
		primaryHandlerChain: HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			*got = r.Header.Clone()
			return nil
		}),
	}
	require.NoError(t, s.provisionUnderscoreHeaders())

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header["Other_header"] = []string{"val"}

	require.NoError(t, s.serveHTTP(httptest.NewRecorder(), req))
	assert.NotContains(t, *got, "Other_header")
}

func TestServer_serveHTTP_PrefixGlobDropsMixedVariant(t *testing.T) {
	got := &http.Header{}
	s := &Server{
		logger:                    zap.NewNop(),
		ExpectedUnderscoreHeaders: []string{"webhook_*"},
		primaryHandlerChain: HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			*got = r.Header.Clone()
			return nil
		}),
	}
	require.NoError(t, s.provisionUnderscoreHeaders())

	// "Webhook-Event_type" has underscores but starts with "Webhook-Event_",
	// which does NOT match the allow prefix "Webhook_", so it is dropped.
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header["Webhook-Event_type"] = []string{"push"}

	require.NoError(t, s.serveHTTP(httptest.NewRecorder(), req))
	assert.NotContains(t, *got, "Webhook-Event_type")
}

func TestServer_serveHTTP_LiteralAsteriskInHeader(t *testing.T) {
	got := &http.Header{}
	s := &Server{
		logger:                    zap.NewNop(),
		ExpectedUnderscoreHeaders: []string{"webhook_*"},
		primaryHandlerChain: HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			*got = r.Header.Clone()
			return nil
		}),
	}
	require.NoError(t, s.provisionUnderscoreHeaders())

	// A header literally named "Webhook_*" matches the prefix rule
	// because "Webhook_" is a prefix of "Webhook_*".
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header["Webhook_*"] = []string{"val"}

	require.NoError(t, s.serveHTTP(httptest.NewRecorder(), req))
	assert.Equal(t, "val", got.Get("Webhook_*"))
}

// --- Combined allowlist ---

func TestServer_serveHTTP_ExactAndPrefixCoexist(t *testing.T) {
	got := &http.Header{}
	s := &Server{
		logger:                    zap.NewNop(),
		ExpectedUnderscoreHeaders: []string{"user_id", "webhook_*"},
		primaryHandlerChain: HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			*got = r.Header.Clone()
			return nil
		}),
	}
	require.NoError(t, s.provisionUnderscoreHeaders())

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header["User_id"] = []string{"zeus"}       // exact match → keep
	req.Header["Webhook_event"] = []string{"push"} // prefix match → keep
	req.Header["Other_field"] = []string{"bad"}    // unlisted → drop
	req.Header.Set("User-Id", "attacker")          // hyphenated exact → drop
	req.Header.Set("Webhook-Event", "attacker")    // hyphenated prefix → drop
	req.Header.Set("X-Normal-Header", "ok")        // no underscore, not a variant → pass through

	require.NoError(t, s.serveHTTP(httptest.NewRecorder(), req))
	assert.Equal(t, "zeus", got.Get("User_id"))
	assert.Equal(t, "push", got.Get("Webhook_event"))
	assert.Equal(t, "ok", got.Get("X-Normal-Header"))
	assert.NotContains(t, *got, "Other_field")
	assert.NotContains(t, *got, "User-Id")
	assert.NotContains(t, *got, "Webhook-Event")
}

// --- Allowlist: repeated values ---

// TestServer_serveHTTP_AllowlistDropsRepeatedExact verifies that an
// allowlisted header arriving with multiple values (repeated field)
// is dropped entirely as a safeguard against header injection.
func TestServer_serveHTTP_AllowlistDropsRepeatedExact(t *testing.T) {
	got := &http.Header{}
	s := &Server{
		logger:                    zap.NewNop(),
		ExpectedUnderscoreHeaders: []string{"user_id"},
		primaryHandlerChain: HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			*got = r.Header.Clone()
			return nil
		}),
	}
	require.NoError(t, s.provisionUnderscoreHeaders())

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header["User_id"] = []string{"zeus", "injected"}

	require.NoError(t, s.serveHTTP(httptest.NewRecorder(), req))
	assert.NotContains(t, *got, "User_id")
}

// TestServer_serveHTTP_AllowlistDropsRepeatedPrefixGlob verifies that a
// glob-matched header arriving with multiple values is dropped entirely.
func TestServer_serveHTTP_AllowlistDropsRepeatedPrefixGlob(t *testing.T) {
	got := &http.Header{}
	s := &Server{
		logger:                    zap.NewNop(),
		ExpectedUnderscoreHeaders: []string{"webhook_*"},
		primaryHandlerChain: HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			*got = r.Header.Clone()
			return nil
		}),
	}
	require.NoError(t, s.provisionUnderscoreHeaders())

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header["Webhook_event"] = []string{"push", "injected"}

	require.NoError(t, s.serveHTTP(httptest.NewRecorder(), req))
	assert.NotContains(t, *got, "Webhook_event")
}

// TestServer_serveHTTP_LogsRepeatedValueDrop verifies that dropping an
// allowlisted header with repeated values emits a warn-level log with
// the header name and value count.
func TestServer_serveHTTP_LogsRepeatedValueDrop(t *testing.T) {
	var buf bytes.Buffer
	s := &Server{
		logger:                    testLogger(buf.Write),
		ExpectedUnderscoreHeaders: []string{"user_id"},
		primaryHandlerChain: HandlerFunc(func(http.ResponseWriter, *http.Request) error {
			return nil
		}),
	}
	require.NoError(t, s.provisionUnderscoreHeaders())

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header["User_id"] = []string{"zeus", "injected"}

	require.NoError(t, s.serveHTTP(httptest.NewRecorder(), req))
	assert.Contains(t, buf.String(), `"level":"warn"`)
	assert.Contains(t, buf.String(), `"msg":"dropping allowlisted underscore header with repeated values (possible spoofing)"`)
	assert.Contains(t, buf.String(), `"header":"User_id"`)
	assert.Contains(t, buf.String(), `"count":2`)
}

// TestServer_serveHTTP_LogsHyphenatedVariantDrop verifies that dropping a
// hyphenated variant of an allowlisted header emits a debug-level log.
func TestServer_serveHTTP_LogsHyphenatedVariantDrop(t *testing.T) {
	var buf bytes.Buffer
	s := &Server{
		logger:                    testLogger(buf.Write),
		ExpectedUnderscoreHeaders: []string{"user_id"},
		primaryHandlerChain: HandlerFunc(func(http.ResponseWriter, *http.Request) error {
			return nil
		}),
	}
	require.NoError(t, s.provisionUnderscoreHeaders())

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set("User-Id", "attacker")

	require.NoError(t, s.serveHTTP(httptest.NewRecorder(), req))
	assert.Contains(t, buf.String(), `"level":"debug"`)
	assert.Contains(t, buf.String(), `"msg":"dropping hyphenated variant of expected underscore header"`)
	assert.Contains(t, buf.String(), `"header":"User-Id"`)
}

// --- Validation ---

func TestServer_provisionUnderscoreHeaders_EmptyListIsNoOp(t *testing.T) {
	s := &Server{ExpectedUnderscoreHeaders: []string{}}
	// Empty slice is treated as "no allowlist" — provisionUnderscoreHeaders
	// returns nil (no error) because len == 0 is a no-op.
	assert.NoError(t, s.provisionUnderscoreHeaders())
}

func TestServer_provisionUnderscoreHeaders_RejectsNoUnderscore(t *testing.T) {
	s := &Server{ExpectedUnderscoreHeaders: []string{"content-type"}}
	assert.Error(t, s.provisionUnderscoreHeaders())
}

func TestServer_provisionUnderscoreHeaders_RejectsBareWildcard(t *testing.T) {
	s := &Server{ExpectedUnderscoreHeaders: []string{"*"}}
	assert.Error(t, s.provisionUnderscoreHeaders())
}

func TestServer_provisionUnderscoreHeaders_RejectsMidGlob(t *testing.T) {
	s := &Server{ExpectedUnderscoreHeaders: []string{"f*oo_bar"}}
	assert.Error(t, s.provisionUnderscoreHeaders())
}

func TestServer_provisionUnderscoreHeaders_RejectsLeadingGlob(t *testing.T) {
	s := &Server{ExpectedUnderscoreHeaders: []string{"*_foo"}}
	assert.Error(t, s.provisionUnderscoreHeaders())
}

func TestServer_provisionUnderscoreHeaders_RejectsNonASCII(t *testing.T) {
	s := &Server{ExpectedUnderscoreHeaders: []string{"uşer_id"}}
	assert.Error(t, s.provisionUnderscoreHeaders())
}

func TestServer_provisionUnderscoreHeaders_ValidExact(t *testing.T) {
	s := &Server{ExpectedUnderscoreHeaders: []string{"user_id"}}
	assert.NoError(t, s.provisionUnderscoreHeaders())
}

func TestServer_provisionUnderscoreHeaders_ValidGlob(t *testing.T) {
	s := &Server{ExpectedUnderscoreHeaders: []string{"webhook_*"}}
	assert.NoError(t, s.provisionUnderscoreHeaders())
}

func TestServer_provisionUnderscoreHeaders_ValidMixed(t *testing.T) {
	s := &Server{ExpectedUnderscoreHeaders: []string{"__user-id"}}
	assert.NoError(t, s.provisionUnderscoreHeaders())
}

func TestServer_provisionUnderscoreHeaders_DeduplicatesSilently(t *testing.T) {
	s := &Server{ExpectedUnderscoreHeaders: []string{"user_id", "user_id"}}
	require.NoError(t, s.provisionUnderscoreHeaders())
	assert.Len(t, s.underscoreExactAllow, 1)
}

// TestServer_SpaceInHeaderNameReturnsBadRequest documents why the underscore
// filter does not also strip space-named headers: Go's HTTP parser rejects a
// space in a field name with 400 before any handler runs, so such a request
// can never reach Caddy's pipeline.
func TestServer_SpaceInHeaderNameReturnsBadRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("handler must not be reached; got headers %v", r.Header)
	}))
	t.Cleanup(srv.Close)

	addr := strings.TrimPrefix(srv.URL, "http://")
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))

	_, err = conn.Write([]byte("GET / HTTP/1.1\r\n" +
		"Host: " + addr + "\r\n" +
		"Remote User: attacker\r\n" +
		"Connection: close\r\n\r\n"))
	require.NoError(t, err)

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestServer_DetermineTrustedProxy_MatchRightMostUntrustedFirst(t *testing.T) {
	localPrivatePrefix, _ := netip.ParsePrefix("10.0.0.0/8")

	server := &Server{
		trustedProxies: &StaticIPRange{
			ranges: []netip.Prefix{localPrivatePrefix},
		},
		ClientIPHeaders:      []string{"CF-Connecting-IP", "X-Forwarded-For"},
		TrustedProxiesStrict: 1,
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header.Set("CF-Connecting-IP", "10.0.0.1, 90.100.110.120, 10.0.0.2, 10.0.0.3")
	req.Header.Set("X-Forwarded-For", "30.30.30.30, 45.54.45.54, 10.0.0.4")

	trusted, clientIP := determineTrustedProxy(req, server)

	assert.True(t, trusted)
	assert.Equal(t, clientIP, "90.100.110.120")
}

// TestServer_BuildHTTP3ServerEnablesWebTransport asserts that the http3.Server
// Caddy builds advertises WebTransport in its SETTINGS and wires the
// prerequisites webtransport.Server.Upgrade relies on: DATAGRAM support,
// a non-nil ConnContext hook (used to stash the underlying *quic.Conn for
// Upgrade to retrieve), and QUIC stream reset partial delivery.
func TestServer_BuildHTTP3ServerEnablesWebTransport(t *testing.T) {
	s := &Server{}
	h3 := s.buildHTTP3Server(&tls.Config{})

	assert.NotNil(t, h3, "expected non-nil http3.Server")
	assert.True(t, h3.EnableDatagrams, "EnableDatagrams must be true for WebTransport DATAGRAMs")
	assert.NotEmpty(t, h3.AdditionalSettings, "AdditionalSettings must advertise WebTransport enablement")
	assert.NotNil(t, h3.ConnContext, "ConnContext must be set so webtransport.Server.Upgrade can retrieve the *quic.Conn")
	assert.NotNil(t, h3.QUICConfig, "QUICConfig must be set")
	assert.True(t, h3.QUICConfig.EnableStreamResetPartialDelivery, "EnableStreamResetPartialDelivery is required by webtransport-go")
}

// TestServer_BuildHTTP3ServerAppliesHandlerAndTLS is a smoke test for the
// non-WebTransport fields of the constructed http3.Server, guarding against a
// refactor accidentally dropping them.
func TestServer_BuildHTTP3ServerAppliesHandlerAndTLS(t *testing.T) {
	s := &Server{MaxHeaderBytes: 4096}
	tlsCfg := &tls.Config{}
	h3 := s.buildHTTP3Server(tlsCfg)

	assert.Same(t, s, h3.Handler, "http3.Server.Handler should be the caddyhttp.Server itself")
	assert.Same(t, tlsCfg, h3.TLSConfig, "http3.Server.TLSConfig should be the config passed in")
	assert.Equal(t, 4096, h3.MaxHeaderBytes)
}
