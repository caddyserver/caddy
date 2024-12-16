package caddyhttp

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
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

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
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

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
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

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
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
