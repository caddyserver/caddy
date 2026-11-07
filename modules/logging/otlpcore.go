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

	"go.opentelemetry.io/contrib/bridges/otelzap"
	"go.opentelemetry.io/contrib/exporters/autoexport"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.uber.org/zap/zapcore"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func init() {
	caddy.RegisterModule(OTLPCore{})
}

// OTLPCore exports log entries as OpenTelemetry log records, in addition
// to the log's writer. The exporter is configured with the standard
// OTEL_* environment variables, such as OTEL_EXPORTER_OTLP_ENDPOINT and
// OTEL_EXPORTER_OTLP_PROTOCOL. Set the log's output to discard to only
// export the entries. Encoder filters, such as those of the filter format,
// do not apply to exported records.
//
//	log {
//		output discard
//		core otlp
//	}
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
	c.Core = otelzap.NewCore("github.com/caddyserver/caddy/v2",
		otelzap.WithLoggerProvider(provider),
		otelzap.WithVersion(version),
	)

	return nil
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
//	core otlp
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

var globalLoggerProvider loggerProvider

// loggerProvider shares one exporter between all logs and across config reloads.
type loggerProvider struct {
	mu       sync.Mutex
	provider *sdklog.LoggerProvider
	users    int
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
	defer p.mu.Unlock()

	p.users--
	if p.users > 0 {
		return nil
	}

	provider := p.provider
	p.provider = nil
	if err := provider.Shutdown(context.Background()); err != nil {
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
)
