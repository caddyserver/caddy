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

package caddypki

import (
	"crypto/x509"
	"testing"
	"time"
)

func TestCA_needsRenewal(t *testing.T) {
	now := time.Now()

	// cert with 100 days lifetime; last 20% = 20 days before expiry
	// So renewal window starts at (NotAfter - 20 days)
	makeCert := func(daysUntilExpiry int, lifetimeDays int) *x509.Certificate {
		notAfter := now.AddDate(0, 0, daysUntilExpiry)
		notBefore := notAfter.AddDate(0, 0, -lifetimeDays)
		return &x509.Certificate{NotBefore: notBefore, NotAfter: notAfter}
	}

	tests := []struct {
		name   string
		ca     *CA
		cert   *x509.Certificate
		expect bool
	}{
		{
			name:   "inside renewal window with ratio 0.2",
			ca:     &CA{RenewalWindowRatio: 0.2},
			cert:   makeCert(10, 100),
			expect: true,
		},
		{
			name:   "outside renewal window with ratio 0.2",
			ca:     &CA{RenewalWindowRatio: 0.2},
			cert:   makeCert(50, 100),
			expect: false,
		},
		{
			name:   "outside renewal window with 21 days left",
			ca:     &CA{RenewalWindowRatio: 0.2},
			cert:   makeCert(21, 100),
			expect: false,
		},
		{
			name:   "just inside renewal window with ratio 0.5",
			ca:     &CA{RenewalWindowRatio: 0.5},
			cert:   makeCert(30, 100),
			expect: true,
		},
		{
			name:   "zero ratio uses default",
			ca:     &CA{RenewalWindowRatio: 0},
			cert:   makeCert(10, 100),
			expect: true,
		},
		{
			name:   "invalid ratio uses default",
			ca:     &CA{RenewalWindowRatio: 1.5},
			cert:   makeCert(10, 100),
			expect: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.ca.needsRenewal(tt.cert)
			if got != tt.expect {
				t.Errorf("needsRenewal() = %v, want %v", got, tt.expect)
			}
		})
	}
}
