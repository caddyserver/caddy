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
	"net/http"

	"github.com/caddyserver/caddy/v2"
)

func init() {
	caddy.RegisterModule(AdminMetrics{})
}

// AdminMetrics - this module serves a metrics endpoint so that any gathered
// metrics can be exposed for scraping. This module is not configurable, and
// is permanently mounted to the admin API endpoint at "/metrics".
// See the Metrics module for a configurable endpoint that is usable if the
// Admin API is disabled.
type AdminMetrics struct{}

// CaddyModule returns the Caddy module information.
func (AdminMetrics) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "admin.api.metrics",
		New: func() caddy.Module { return new(AdminMetrics) },
	}
}

// Routes returns a route for the /metrics endpoint.
func (m *AdminMetrics) Routes() []caddy.AdminRoute {
	metricsHandler := createMetricsHandler(nil)
	h := caddy.AdminHandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		metricsHandler.ServeHTTP(w, r)
		return nil
	})
	return []caddy.AdminRoute{{Pattern: "/metrics", Handler: h}}
}

// Interface guards
var (
	_ caddy.AdminRouter = (*AdminMetrics)(nil)
)
