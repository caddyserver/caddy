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

package reverseproxy

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/caddyserver/caddy/v2"
)

func init() {
	caddy.RegisterModule(adminUpstreams{})
}

// adminUpstreams is a module that provides the
// /reverse_proxy/upstreams endpoint for the Caddy admin
// API. This allows for checking the health of configured
// reverse proxy upstreams in the pool.
type adminUpstreams struct{}

// upstreamStatus holds the status of a particular upstream. The endpoint
// returns one entry per HEALTH TARGET — that is, per (address, active
// health check config) pair, not per address: handlers that dial the same
// address with different active health checks keep independent health
// state (see hostKeySuffix), and collapsing them here would have to
// invent aggregation semantics the consumer can't undo. Consumers must
// treat (address, health_check) as the entry's identity; health_check is
// "" for upstreams with no active health checks configured.
type upstreamStatus struct {
	Address     string `json:"address"`
	HealthCheck string `json:"health_check,omitempty"`
	NumRequests int    `json:"num_requests"`
	Fails       int    `json:"fails"`
}

// CaddyModule returns the Caddy module information.
func (adminUpstreams) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "admin.api.reverse_proxy",
		New: func() caddy.Module { return new(adminUpstreams) },
	}
}

// Routes returns a route for the /reverse_proxy/upstreams endpoint.
func (al adminUpstreams) Routes() []caddy.AdminRoute {
	return []caddy.AdminRoute{
		{
			Pattern: "/reverse_proxy/upstreams",
			Handler: caddy.AdminHandlerFunc(al.handleUpstreams),
		},
	}
}

// handleUpstreams reports the status of the reverse proxy
// upstream pool.
func (adminUpstreams) handleUpstreams(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodGet {
		return caddy.APIError{
			HTTPStatus: http.StatusMethodNotAllowed,
			Err:        fmt.Errorf("method not allowed"),
		}
	}

	// Prep for a JSON response
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)

	// Collect the results to respond with
	results := []upstreamStatus{}
	knownHosts := make(map[string]struct{})

	// Iterate over the static upstream pool (needs to be fast)
	var rangeErr error
	hosts.Range(func(key, val any) bool {
		poolKey, ok := key.(string)
		if !ok {
			rangeErr = caddy.APIError{
				HTTPStatus: http.StatusInternalServerError,
				Err:        fmt.Errorf("could not type assert upstream address"),
			}
			return false
		}
		// pool keys carry the health-check fingerprint of their health
		// target (see hostKeySuffix); split it out so the address stays
		// plain and the fingerprint is the entry's public discriminator
		address := hostKeyAddress(poolKey)
		fingerprint := hostKeyFingerprint(poolKey)

		upstream, ok := val.(*Host)
		if !ok {
			rangeErr = caddy.APIError{
				HTTPStatus: http.StatusInternalServerError,
				Err:        fmt.Errorf("could not type assert upstream struct"),
			}
			return false
		}

		knownHosts[address] = struct{}{}

		results = append(results, upstreamStatus{
			Address:     address,
			HealthCheck: fingerprint,
			NumRequests: upstream.NumRequests(),
			Fails:       upstream.Fails(),
		})
		return true
	})

	currentInFlight := getInFlightRequests()
	for address, count := range currentInFlight {
		if _, exists := knownHosts[address]; !exists && count > 0 {
			results = append(results, upstreamStatus{
				Address:     address,
				NumRequests: int(count),
				Fails:       0,
			})
		}
	}

	if rangeErr != nil {
		return rangeErr
	}

	// Also include dynamic upstreams
	dynamicHostsMu.RLock()
	for address, entry := range dynamicHosts {
		results = append(results, upstreamStatus{
			Address:     address,
			NumRequests: entry.host.NumRequests(),
			Fails:       entry.host.Fails(),
		})
	}
	dynamicHostsMu.RUnlock()

	err := enc.Encode(results)
	if err != nil {
		return caddy.APIError{
			HTTPStatus: http.StatusInternalServerError,
			Err:        err,
		}
	}

	return nil
}
