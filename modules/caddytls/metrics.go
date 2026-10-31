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
	"errors"
	"sync"

	"github.com/mholt/acmez/v3/acme"
	"github.com/prometheus/client_golang/prometheus"
)

// tlsMetrics are the TLS app's Prometheus collectors. They are created once
// per process, so counts carry across config reloads, and registered with
// each config's registry.
//
// CARDINALITY PROTECTION: every label has a fixed set of values. With
// on-demand TLS, certificate names are chosen by clients, so no certificate
// name, SAN, account or ask URL is ever used as a label. The issuer label is
// the key of a configured issuer.
var tlsMetrics = struct {
	once           sync.Once
	certOperations *prometheus.CounterVec
	onDemandAsks   *prometheus.CounterVec
}{}

// certMetricEvents are the events the certificate operation counters are fed
// by. They must reach onEvent even when nothing is subscribed to them.
var certMetricEvents = map[string]bool{
	"cert_obtained": true,
	"cert_failed":   true,
}

func initTLSMetrics(registry *prometheus.Registry) error {
	const ns, sub = "caddy", "tls"

	tlsMetrics.once.Do(func() {
		tlsMetrics.certOperations = prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns,
			Subsystem: sub,
			Name:      "certificate_operations_total",
			Help:      "Total number of managed certificate obtain and renewal attempts, by outcome.",
		}, []string{"operation", "issuer", "result", "error_type"})
		tlsMetrics.onDemandAsks = prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns,
			Subsystem: sub,
			Name:      "on_demand_ask_total",
			Help:      "Total number of on-demand TLS permission checks, by result.",
		}, []string{"result"})
	})

	for _, c := range []prometheus.Collector{tlsMetrics.certOperations, tlsMetrics.onDemandAsks} {
		if err := registry.Register(c); err != nil &&
			!errors.Is(err, prometheus.AlreadyRegisteredError{ExistingCollector: c, NewCollector: c}) {
			return err
		}
	}
	return nil
}

// observeCertEvent counts a certificate obtain or renewal outcome from the
// data of a cert_obtained or cert_failed event.
func observeCertEvent(eventName string, data map[string]any) {
	if tlsMetrics.certOperations == nil || !certMetricEvents[eventName] {
		return
	}
	operation := "obtain"
	if renewal, _ := data["renewal"].(bool); renewal {
		operation = "renew"
	}
	if eventName == "cert_obtained" {
		issuer, _ := data["issuer"].(string)
		tlsMetrics.certOperations.WithLabelValues(operation, issuer, "success", "").Inc()
		return
	}
	// The error returned is the last issuer's, so that issuer is the one
	// the failure is counted against.
	var issuer string
	if issuers, _ := data["issuers"].([]string); len(issuers) > 0 {
		issuer = issuers[len(issuers)-1]
	}
	err, _ := data["error"].(error)
	tlsMetrics.certOperations.WithLabelValues(operation, issuer, "failure", certErrorType(err)).Inc()
}

// certErrorType categorizes a certificate obtain or renewal error by its ACME
// problem type.
func certErrorType(err error) string {
	var problemType string
	var problem acme.Problem
	var problemPtr *acme.Problem
	switch {
	case errors.As(err, &problem):
		problemType = problem.Type
	case errors.As(err, &problemPtr):
		problemType = problemPtr.Type
	default:
		return "other"
	}
	switch problemType {
	case acme.ProblemTypeRateLimited:
		return "rate_limited"
	case acme.ProblemTypeConnection, acme.ProblemTypeDNS, acme.ProblemTypeUnauthorized,
		acme.ProblemTypeIncorrectResponse, acme.ProblemTypeTLS, acme.ProblemTypeCAA:
		return "challenge_failed"
	default:
		return "other"
	}
}

// observeOnDemandAsk counts the result of asking the on-demand permission
// module whether a certificate is allowed.
func observeOnDemandAsk(err error) {
	if tlsMetrics.onDemandAsks == nil {
		return
	}
	result := "allowed"
	switch {
	case errors.Is(err, ErrPermissionDenied):
		result = "denied"
	case err != nil:
		result = "error"
	}
	tlsMetrics.onDemandAsks.WithLabelValues(result).Inc()
}
