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

package caddytls

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/mholt/acmez/v3/acme"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyevents"
)

func mustInitTLSMetrics(t *testing.T) {
	t.Helper()
	if err := initTLSMetrics(prometheus.NewPedanticRegistry()); err != nil {
		t.Fatal(err)
	}
}

func TestInitTLSMetricsRegistersOnEachRegistry(t *testing.T) {
	registry := prometheus.NewPedanticRegistry()
	if err := initTLSMetrics(registry); err != nil {
		t.Fatal(err)
	}
	// A config can be provisioned more than once with the same registry.
	if err := initTLSMetrics(registry); err != nil {
		t.Fatalf("registering twice on one registry: %v", err)
	}
	// A config reload gets a new registry; the same collectors are registered
	// on it, so counts carry across reloads.
	if err := initTLSMetrics(prometheus.NewPedanticRegistry()); err != nil {
		t.Fatalf("registering on a new registry: %v", err)
	}
	tlsMetrics.onDemandAsks.WithLabelValues("allowed")
	if n, err := testutil.GatherAndCount(registry, "caddy_tls_on_demand_ask_total"); err != nil || n == 0 {
		t.Fatalf("on_demand_ask_total not gathered from registry: count=%d err=%v", n, err)
	}
}

func TestObserveCertEvent(t *testing.T) {
	mustInitTLSMetrics(t)
	count := func(labels ...string) float64 {
		return testutil.ToFloat64(tlsMetrics.certOperations.WithLabelValues(labels...))
	}

	const issuer = "acme-v02.api.letsencrypt.org-directory"
	tests := []struct {
		name   string
		event  string
		data   map[string]any
		labels []string
	}{
		{
			name:   "obtained",
			event:  "cert_obtained",
			data:   map[string]any{"renewal": false, "issuer": issuer, "identifier": "a.example.com"},
			labels: []string{"obtain", issuer, "success", ""},
		},
		{
			name:   "renewed",
			event:  "cert_obtained",
			data:   map[string]any{"renewal": true, "issuer": issuer, "identifier": "b.example.com"},
			labels: []string{"renew", issuer, "success", ""},
		},
		{
			name:  "obtain rate limited by the last issuer",
			event: "cert_failed",
			data: map[string]any{
				"renewal":    false,
				"issuers":    []string{"local", issuer},
				"identifier": "c.example.com",
				"error":      fmt.Errorf("[c.example.com] Obtain: %w", acme.Problem{Type: acme.ProblemTypeRateLimited}),
			},
			labels: []string{"obtain", issuer, "failure", "rate_limited"},
		},
		{
			name:  "renewal challenge failed",
			event: "cert_failed",
			data: map[string]any{
				"renewal": true,
				"issuers": []string{issuer},
				"error":   acme.Problem{Type: acme.ProblemTypeConnection},
			},
			labels: []string{"renew", issuer, "failure", "challenge_failed"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			before := count(tc.labels...)
			observeCertEvent(tc.event, tc.data)
			if got := count(tc.labels...) - before; got != 1 {
				t.Fatalf("counter %v increased by %v, want 1", tc.labels, got)
			}
		})
	}

	t.Run("other events are not counted", func(t *testing.T) {
		before := testutil.CollectAndCount(tlsMetrics.certOperations)
		observeCertEvent("cert_obtaining", map[string]any{"renewal": false, "identifier": "new.example.com"})
		observeCertEvent("tls_get_certificate", map[string]any{"client_hello": nil})
		if after := testutil.CollectAndCount(tlsMetrics.certOperations); after != before {
			t.Fatalf("series went from %d to %d", before, after)
		}
	})
}

func TestCertErrorType(t *testing.T) {
	tests := []struct {
		err  error
		want string
	}{
		{acme.Problem{Type: acme.ProblemTypeRateLimited}, "rate_limited"},
		{&acme.Problem{Type: acme.ProblemTypeRateLimited}, "rate_limited"},
		{fmt.Errorf("wrapped: %w", acme.Problem{Type: acme.ProblemTypeDNS}), "challenge_failed"},
		{acme.Problem{Type: acme.ProblemTypeUnauthorized}, "challenge_failed"},
		{acme.Problem{Type: acme.ProblemTypeIncorrectResponse}, "challenge_failed"},
		{acme.Problem{Type: acme.ProblemTypeTLS}, "challenge_failed"},
		{acme.Problem{Type: acme.ProblemTypeCAA}, "challenge_failed"},
		{acme.Problem{Type: acme.ProblemTypeBadNonce}, "other"},
		{errors.New("connection refused"), "other"},
		{nil, "other"},
	}
	for _, tc := range tests {
		if got := certErrorType(tc.err); got != tc.want {
			t.Errorf("certErrorType(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
}

func TestObserveOnDemandAsk(t *testing.T) {
	mustInitTLSMetrics(t)
	tests := []struct {
		err  error
		want string
	}{
		{nil, "allowed"},
		{fmt.Errorf("a.example.com: %w ask - non-2xx status code 403", ErrPermissionDenied), "denied"},
		{errors.New("checking ask endpoint: connection refused"), "error"},
	}
	for _, tc := range tests {
		before := testutil.ToFloat64(tlsMetrics.onDemandAsks.WithLabelValues(tc.want))
		observeOnDemandAsk(tc.err)
		if got := testutil.ToFloat64(tlsMetrics.onDemandAsks.WithLabelValues(tc.want)) - before; got != 1 {
			t.Errorf("observeOnDemandAsk(%v): %q increased by %v, want 1", tc.err, tc.want, got)
		}
	}
}

func TestShouldEmitIncludesMetricEvents(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	events := new(caddyevents.App)
	if err := events.Provision(ctx); err != nil {
		t.Fatal(err)
	}
	tlsApp := &TLS{events: events}

	// The metrics need these whether or not anything observes them.
	for name := range certMetricEvents {
		if !tlsApp.shouldEmit(name) {
			t.Errorf("shouldEmit(%q) = false, want true", name)
		}
	}
	// Any other event is emitted only if the events app would emit it.
	for _, name := range []string{"tls_get_certificate", "cert_obtaining", "cached_managed_cert"} {
		if got, want := tlsApp.shouldEmit(name), events.ShouldEmit(name); got != want {
			t.Errorf("shouldEmit(%q) = %v, want %v as the events app reports", name, got, want)
		}
	}
}
