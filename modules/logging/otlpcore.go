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
	"fmt"
	"sync"
	"time"

	"go.opentelemetry.io/contrib/bridges/otelzap"
	"go.opentelemetry.io/contrib/exporters/autoexport"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap/zapcore"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func init() {
	caddy.RegisterModule(OTLPCore{})
}

// OTLPCore exports log entries as OpenTelemetry log records, in addition
// to the log's writer. The log's level, sampling, and include and exclude
// lists apply to exported entries too. Set the log's output to discard to
// only export the entries:
//
//	{
//		"writer": {"output": "discard"},
//		"core": {"module": "otlp"}
//	}
//
// Each record carries the entry's level, message, and fields as
// attributes. The logger name, such as http.log.access, is the
// instrumentation scope. Access logs are linked to the span of the
// tracing handler.
//
// The exporter is configured with the standard OpenTelemetry environment
// variables:
//
//   - OTEL_LOGS_EXPORTER: otlp (default), console, or none
//   - OTEL_EXPORTER_OTLP_PROTOCOL: http/protobuf (default) or grpc
//   - OTEL_EXPORTER_OTLP_ENDPOINT, OTEL_EXPORTER_OTLP_HEADERS,
//     OTEL_EXPORTER_OTLP_TIMEOUT, OTEL_EXPORTER_OTLP_COMPRESSION,
//     OTEL_EXPORTER_OTLP_INSECURE, OTEL_EXPORTER_OTLP_CERTIFICATE,
//     OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE, OTEL_EXPORTER_OTLP_CLIENT_KEY
//   - the OTEL_EXPORTER_OTLP_LOGS_* variant of each variable above, which
//     takes precedence
//   - OTEL_SERVICE_NAME and OTEL_RESOURCE_ATTRIBUTES
//   - OTEL_BLRP_SCHEDULE_DELAY, OTEL_BLRP_EXPORT_TIMEOUT,
//     OTEL_BLRP_MAX_QUEUE_SIZE, and OTEL_BLRP_MAX_EXPORT_BATCH_SIZE
//   - OTEL_LOGRECORD_ATTRIBUTE_COUNT_LIMIT and
//     OTEL_LOGRECORD_ATTRIBUTE_VALUE_LENGTH_LIMIT
//
// All logs share one exporter, which survives config reloads. Pending
// records are flushed, for up to 5 seconds, when the last log using it
// is unloaded.
//
// The log's format only shapes the writer's output, except for two
// formats. The field filters of the filter format apply to exported
// records too, so redacted fields stay redacted. Fields added by the
// append format are NOT exported. To attach information about the Caddy instance to
// exported records, set it as resource attributes instead, for example
// OTEL_RESOURCE_ATTRIBUTES=host.name=web-1,deployment.environment=prod.
type OTLPCore struct {
	zapcore.Core `json:"-"`

	provider *sdklog.LoggerProvider
}

// CaddyModule returns the Caddy module information.
func (OTLPCore) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.logging.cores.otlp",
		New: func() caddy.Module { return new(OTLPCore) },
	}
}

// Provision sets up the core.
func (c *OTLPCore) Provision(ctx caddy.Context) error {
	provider, err := globalLoggerProvider.acquire(ctx)
	if err != nil {
		return err
	}
	c.provider = provider

	version, _ := caddy.Version()
	c.Core = &otlpCore{Core: otelzap.NewCore("github.com/caddyserver/caddy/v2",
		otelzap.WithLoggerProvider(provider),
		otelzap.WithVersion(version),
	)}

	return nil
}

// ConfigureFromLogEncoder picks up the field filters of the log's format.
func (c *OTLPCore) ConfigureFromLogEncoder(enc zapcore.Encoder) error {
	core := c.Core.(*otlpCore)
	for {
		switch e := enc.(type) {
		case *FilterEncoder:
			core.filters = append(core.filters, e.Fields)
			enc = e.wrapped
		case *AppendEncoder:
			enc = e.wrapped
		case *JournaldEncoder:
			enc = e.Encoder
		default:
			return nil
		}
	}
}

// Cleanup flushes pending records when the last OTLP core is unloaded.
func (c *OTLPCore) Cleanup() error {
	if c.provider == nil {
		return nil
	}
	c.provider = nil

	return globalLoggerProvider.release()
}

// UnmarshalCaddyfile sets up the module from Caddyfile tokens. Syntax:
//
//	otlp
func (c *OTLPCore) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume core name
	if d.NextArg() {
		return d.ArgErr()
	}
	if d.NextBlock(0) {
		return d.Errf("unrecognized subdirective %s", d.Val())
	}

	return nil
}

// otlpCore prepares fields before handing them to the OpenTelemetry bridge.
type otlpCore struct {
	zapcore.Core
	// filters of the nested filter formats, outermost first
	filters []map[string]LogFieldFilter
}

func (c *otlpCore) With(fields []zapcore.Field) zapcore.Core {
	return &otlpCore{Core: c.Core.With(c.prepare(fields)), filters: c.filters}
}

func (c *otlpCore) Check(ent zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	// the bridge would register itself and skip prepare
	if c.Enabled(ent.Level) {
		return ce.AddCore(ent, c)
	}
	return ce
}

func (c *otlpCore) Write(ent zapcore.Entry, fields []zapcore.Field) error {
	return c.Core.Write(ent, c.prepare(fields))
}

// prepare applies the field filters the way FilterEncoder does, and
// links the record to the span whose IDs the tracing handler logged.
func (c *otlpCore) prepare(fields []zapcore.Field) []zapcore.Field {
	prepared := make([]zapcore.Field, len(fields), len(fields)+1)
	copy(prepared, fields)
	for _, filters := range c.filters {
		for i, f := range prepared {
			if filter, ok := filters[f.Key]; ok {
				prepared[i] = filter.Filter(f)
			} else if marsh, ok := f.Interface.(zapcore.ObjectMarshaler); ok && f.Type == zapcore.ObjectMarshalerType {
				prepared[i].Interface = logObjectMarshalerWrapper{
					enc:   FilterEncoder{Fields: filters, keyPrefix: f.Key + ">"},
					marsh: marsh,
				}
			}
		}
	}

	var traceID trace.TraceID
	var spanID trace.SpanID
	for _, f := range prepared {
		if f.Type == zapcore.StringType {
			switch f.Key {
			case "traceID":
				traceID, _ = trace.TraceIDFromHex(f.String)
			case "spanID":
				spanID, _ = trace.SpanIDFromHex(f.String)
			}
		}
	}

	if traceID.IsValid() && spanID.IsValid() {
		spanCtx := trace.NewSpanContext(trace.SpanContextConfig{TraceID: traceID, SpanID: spanID})
		// the bridge takes the record's span from a context field, which encoders skip
		prepared = append(prepared, zapcore.Field{
			Type:      zapcore.SkipType,
			Interface: trace.ContextWithSpanContext(context.Background(), spanCtx),
		})
	}

	return prepared
}

var globalLoggerProvider = loggerProvider{shutdownTimeout: 5 * time.Second}

// loggerProvider shares one exporter between all logs and across config reloads.
type loggerProvider struct {
	mu       sync.Mutex
	provider *sdklog.LoggerProvider
	users    int
	// bounds the flush so a stalled exporter cannot hang config unloading
	shutdownTimeout time.Duration
}

func (p *loggerProvider) acquire(ctx context.Context) (*sdklog.LoggerProvider, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.provider == nil {
		version, _ := caddy.Version()
		res, err := resource.Merge(resource.Default(), resource.NewSchemaless(
			semconv.WebEngineName("Caddy"),
			semconv.WebEngineVersion(version),
		))
		if err != nil {
			return nil, fmt.Errorf("building OTLP logs resource: %w", err)
		}

		exporter, err := autoexport.NewLogExporter(ctx)
		if err != nil {
			return nil, fmt.Errorf("creating OTLP log exporter: %w", err)
		}

		p.provider = sdklog.NewLoggerProvider(
			sdklog.WithProcessor(sdklog.NewBatchProcessor(exporter)),
			sdklog.WithResource(res),
		)
	}
	p.users++

	return p.provider, nil
}

func (p *loggerProvider) release() error {
	p.mu.Lock()
	p.users--
	if p.users > 0 {
		p.mu.Unlock()
		return nil
	}
	provider := p.provider
	p.provider = nil
	timeout := p.shutdownTimeout
	p.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := provider.Shutdown(ctx); err != nil {
		return fmt.Errorf("shutting down OTLP logger provider: %w", err)
	}

	return nil
}

// Interface guards
var (
	_ zapcore.Core          = (*OTLPCore)(nil)
	_ caddy.Provisioner     = (*OTLPCore)(nil)
	_ caddy.CleanerUpper    = (*OTLPCore)(nil)
	_ caddyfile.Unmarshaler = (*OTLPCore)(nil)

	_ caddy.ConfiguresFromLogEncoder = (*OTLPCore)(nil)
)
