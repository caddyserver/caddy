// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package logging

import (
	"context"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"

	"github.com/caddyserver/caddy/v2"
)

type otlpCollector struct {
	mu      sync.Mutex
	records map[string]*logspb.LogRecord
	scopes  map[string]string
}

func newOTLPCollector(t *testing.T) *otlpCollector {
	t.Helper()

	c := &otlpCollector{records: map[string]*logspb.LogRecord{}, scopes: map[string]string{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		var req collogspb.ExportLogsServiceRequest
		if err := proto.Unmarshal(body, &req); err != nil {
			t.Error(err)
			return
		}

		c.mu.Lock()
		defer c.mu.Unlock()
		for _, rl := range req.GetResourceLogs() {
			for _, sl := range rl.GetScopeLogs() {
				for _, lr := range sl.GetLogRecords() {
					msg := lr.GetBody().GetStringValue()
					c.records[msg] = lr
					c.scopes[msg] = sl.GetScope().GetName()
				}
			}
		}
	}))
	t.Cleanup(srv.Close)

	t.Setenv("OTEL_LOGS_EXPORTER", "otlp")
	t.Setenv("OTEL_EXPORTER_OTLP_LOGS_PROTOCOL", "http/protobuf")
	t.Setenv("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", srv.URL+"/v1/logs")

	return c
}

func (c *otlpCollector) record(msg string) (*logspb.LogRecord, string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.records[msg], c.scopes[msg]
}

func provisionOTLPCore(t *testing.T) *OTLPCore {
	t.Helper()

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	t.Cleanup(cancel)

	core := new(OTLPCore)
	if err := core.Provision(ctx); err != nil {
		t.Fatal(err)
	}

	return core
}

func TestOTLPCoreExportsRecords(t *testing.T) {
	collector := newOTLPCollector(t)
	core := provisionOTLPCore(t)

	zap.New(core).Named("http.log.access").Warn("handled request", zap.Int("status", 502))
	if err := core.Cleanup(); err != nil {
		t.Fatal(err)
	}

	rec, scope := collector.record("handled request")
	if rec == nil {
		t.Fatal("expected the record to be exported on cleanup")
	}
	if scope != "http.log.access" {
		t.Errorf("expected the logger name as scope, got %q", scope)
	}
	if rec.GetSeverityText() != "warn" || rec.GetSeverityNumber() != logspb.SeverityNumber_SEVERITY_NUMBER_WARN {
		t.Errorf("unexpected severity %s (%d)", rec.GetSeverityText(), rec.GetSeverityNumber())
	}
	if attrs := rec.GetAttributes(); len(attrs) != 1 || attrs[0].GetKey() != "status" || attrs[0].GetValue().GetIntValue() != 502 {
		t.Errorf("unexpected attributes %v", attrs)
	}
}

func TestOTLPCoreSharesProviderAcrossReloads(t *testing.T) {
	collector := newOTLPCollector(t)
	oldCore := provisionOTLPCore(t)
	newCore := provisionOTLPCore(t)

	if err := oldCore.Cleanup(); err != nil {
		t.Fatal(err)
	}
	zap.New(newCore).Info("after reload")
	if err := newCore.Cleanup(); err != nil {
		t.Fatal(err)
	}

	if rec, _ := collector.record("after reload"); rec == nil {
		t.Fatal("expected the provider to outlive the unloaded config")
	}
	if globalLoggerProvider.provider != nil {
		t.Error("expected the provider to be shut down with the last core")
	}
}

func TestOTLPCoreAppliesFieldFilters(t *testing.T) {
	collector := newOTLPCollector(t)
	core := provisionOTLPCore(t)
	err := core.ConfigureFromLogEncoder(&AppendEncoder{wrapped: &FilterEncoder{Fields: map[string]LogFieldFilter{
		"user_id":           DeleteFilter{},
		"request>remote_ip": &ReplaceFilter{Value: "REDACTED"},
	}}})
	if err != nil {
		t.Fatal(err)
	}

	zap.New(core).Info("filtered",
		zap.Object("request", testObject{"remote_ip": "192.0.2.1", "host": "example.com"}),
		zap.String("user_id", "kevin"),
		zap.Int("status", 200),
	)
	if err := core.Cleanup(); err != nil {
		t.Fatal(err)
	}

	rec, _ := collector.record("filtered")
	if rec == nil {
		t.Fatal("expected the record to be exported")
	}
	attrs := map[string]*commonpb.AnyValue{}
	for _, kv := range rec.GetAttributes() {
		attrs[kv.GetKey()] = kv.GetValue()
	}
	if _, ok := attrs["user_id"]; ok {
		t.Error("expected user_id to be deleted")
	}
	if attrs["status"].GetIntValue() != 200 {
		t.Errorf("expected status to be kept, got %v", attrs["status"])
	}
	request := map[string]string{}
	for _, kv := range attrs["request"].GetKvlistValue().GetValues() {
		request[kv.GetKey()] = kv.GetValue().GetStringValue()
	}
	if !reflect.DeepEqual(request, map[string]string{"remote_ip": "REDACTED", "host": "example.com"}) {
		t.Errorf("unexpected request attribute %v", request)
	}
}

func TestOTLPCoreLinksRecordsToSpans(t *testing.T) {
	collector := newOTLPCollector(t)
	core := provisionOTLPCore(t)

	logger := zap.New(core)
	logger.Info("traced", zap.String("traceID", "4bf92f3577b34da6a3ce929d0e0e4736"), zap.String("spanID", "00f067aa0ba902b7"))
	logger.Info("untraced", zap.String("traceID", "not-hex"), zap.String("spanID", "00f067aa0ba902b7"))
	if err := core.Cleanup(); err != nil {
		t.Fatal(err)
	}

	traced, _ := collector.record("traced")
	if got := hex.EncodeToString(traced.GetTraceId()); got != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Errorf("unexpected trace ID %q", got)
	}
	if got := hex.EncodeToString(traced.GetSpanId()); got != "00f067aa0ba902b7" {
		t.Errorf("unexpected span ID %q", got)
	}
	if untraced, _ := collector.record("untraced"); len(untraced.GetTraceId()) != 0 {
		t.Errorf("expected no trace ID for invalid IDs, got %x", untraced.GetTraceId())
	}
}
