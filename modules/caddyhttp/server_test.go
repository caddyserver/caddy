package caddyhttp

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
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

func TestServer_LogRequest_WithTraceID(t *testing.T) {
	s := &Server{}

	extra := new(ExtraLogFields)
	ctx := context.WithValue(context.Background(), ExtraLogFieldsCtxKey, extra)
	extra.Add(zap.String("traceID", "1234567890abcdef"))

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
		"traceID":"1234567890abcdef"
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

func BenchmarkServer_LogRequest_WithTraceID(b *testing.B) {
	s := &Server{}

	extra := new(ExtraLogFields)
	ctx := context.WithValue(context.Background(), ExtraLogFieldsCtxKey, extra)
	extra.Add(zap.String("traceID", "1234567890abcdef"))

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
