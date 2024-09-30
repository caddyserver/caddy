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

	"github.com/caddyserver/caddy/v2"
)

func init() {
	caddy.RegisterModule(AdminMetrics{})
}

// AdminMetrics is a module that serves a metrics endpoint so that any gathered
// metrics can be exposed for scraping. This module is not configurable, and
// is permanently mounted to the admin API endpoint at "/metrics".
// See the Metrics module for a configurable endpoint that is usable if the
// Admin API is disabled.
type AdminMetrics struct {
	registry *prometheus.Registry

	metricsHandler http.Handler
}

// CaddyModule returns the Caddy module information.
func (AdminMetrics) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "admin.api.metrics",
		New: func() caddy.Module { return new(AdminMetrics) },
	}
}

// Provision -
func (m *AdminMetrics) Provision(ctx caddy.Context) error {
	m.registry = ctx.GetMetricsRegistry()
	if m.registry == nil {
		return errors.New("no metrics registry found")
	}
	m.metricsHandler = createMetricsHandler(nil, false, m.registry)
	return nil
}

// Routes returns a route for the /metrics endpoint.
func (m *AdminMetrics) Routes() []caddy.AdminRoute {
	return []caddy.AdminRoute{{Pattern: "/metrics", Handler: caddy.AdminHandlerFunc(m.serveHTTP)}}
}

func (m *AdminMetrics) serveHTTP(w http.ResponseWriter, r *http.Request) error {
	m.metricsHandler.ServeHTTP(w, r)
	return nil
}

// Interface guards
var (
	_ caddy.Provisioner = (*AdminMetrics)(nil)
	_ caddy.AdminRouter = (*AdminMetrics)(nil)
)
