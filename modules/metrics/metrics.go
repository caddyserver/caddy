// Copyright 2020 Matthew Holt and The Caddy Authors
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

package metrics

import (
	"errors"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(Metrics{})
	httpcaddyfile.RegisterHandlerDirective("metrics", parseCaddyfile)
}

// Metrics is a module that serves a /metrics endpoint so that any gathered
// metrics can be exposed for scraping. This module is configurable by end-users
// unlike AdminMetrics.
type Metrics struct {
	metricsHandler http.Handler

	// Disable OpenMetrics negotiation, enabled by default. May be necessary if
	// the produced metrics cannot be parsed by the service scraping metrics.
	DisableOpenMetrics bool `json:"disable_openmetrics,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (Metrics) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.metrics",
		New: func() caddy.Module { return new(Metrics) },
	}
}

type zapLogger struct {
	zl *zap.Logger
}

func (l *zapLogger) Println(v ...any) {
	l.zl.Sugar().Error(v...)
}

// Provision sets up m.
func (m *Metrics) Provision(ctx caddy.Context) error {
	log := ctx.Logger()
	registry := ctx.GetMetricsRegistry()
	if registry == nil {
		return errors.New("no metrics registry found")
	}
	m.metricsHandler = createMetricsHandler(&zapLogger{log}, !m.DisableOpenMetrics, registry)
	return nil
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m Metrics
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}

// UnmarshalCaddyfile sets up the handler from Caddyfile tokens. Syntax:
//
//	metrics [<matcher>] {
//	    disable_openmetrics
//	}
func (m *Metrics) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume directive name
	args := d.RemainingArgs()
	if len(args) > 0 {
		return d.ArgErr()
	}

	for d.NextBlock(0) {
		switch d.Val() {
		case "disable_openmetrics":
			m.DisableOpenMetrics = true
		default:
			return d.Errf("unrecognized subdirective %q", d.Val())
		}
	}
	return nil
}

func (m Metrics) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	m.metricsHandler.ServeHTTP(w, r)
	return nil
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Metrics)(nil)
	_ caddyhttp.MiddlewareHandler = (*Metrics)(nil)
	_ caddyfile.Unmarshaler       = (*Metrics)(nil)
)

func createMetricsHandler(logger promhttp.Logger, enableOpenMetrics bool, registry *prometheus.Registry) http.Handler {
	return promhttp.InstrumentMetricHandler(registry,
		promhttp.HandlerFor(registry, promhttp.HandlerOpts{
			// will only log errors if logger is non-nil
			ErrorLog: logger,

			// Allow OpenMetrics format to be negotiated - largely compatible,
			// except quantile/le label values always have a decimal.
			EnableOpenMetrics: enableOpenMetrics,
		}),
	)
}
