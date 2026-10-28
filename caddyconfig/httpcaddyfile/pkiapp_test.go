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

package httpcaddyfile

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestParsePKIApp_maintenanceIntervalAndRenewalWindowRatio(t *testing.T) {
	input := `{
		pki {
			ca local {
				maintenance_interval 5m
				renewal_window_ratio 0.15
			}
		}
	}
	:8080 {
	}
	`
	adapter := caddyfile.Adapter{ServerType: ServerType{}}
	out, _, err := adapter.Adapt([]byte(input), nil)
	if err != nil {
		t.Fatalf("Adapt failed: %v", err)
	}

	var cfg struct {
		Apps struct {
			PKI struct {
				CertificateAuthorities map[string]struct {
					MaintenanceInterval int64   `json:"maintenance_interval,omitempty"`
					RenewalWindowRatio  float64 `json:"renewal_window_ratio,omitempty"`
				} `json:"certificate_authorities,omitempty"`
			} `json:"pki,omitempty"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(out, &cfg); err != nil {
		t.Fatalf("unmarshal config: %v", err)
	}

	ca, ok := cfg.Apps.PKI.CertificateAuthorities["local"]
	if !ok {
		t.Fatal("expected certificate_authorities.local to exist")
	}
	wantInterval := 5 * time.Minute.Nanoseconds()
	if ca.MaintenanceInterval != wantInterval {
		t.Errorf("maintenance_interval = %d, want %d (5m)", ca.MaintenanceInterval, wantInterval)
	}
	if ca.RenewalWindowRatio != 0.15 {
		t.Errorf("renewal_window_ratio = %v, want 0.15", ca.RenewalWindowRatio)
	}
}

// adaptedPKIConfig runs the given Caddyfile through the adapter and
// returns just the parts of the resulting JSON this test cares about:
// which CAs got a certificate_authorities entry, and whether install_trust
// was set to false for each.
func adaptedPKIConfig(t *testing.T, input string) map[string]struct {
	InstallTrust *bool `json:"install_trust,omitempty"`
} {
	t.Helper()

	adapter := caddyfile.Adapter{ServerType: ServerType{}}
	out, _, err := adapter.Adapt([]byte(input), nil)
	if err != nil {
		t.Fatalf("Adapt failed: %v", err)
	}

	var cfg struct {
		Apps struct {
			PKI struct {
				CertificateAuthorities map[string]struct {
					InstallTrust *bool `json:"install_trust,omitempty"`
				} `json:"certificate_authorities,omitempty"`
			} `json:"pki,omitempty"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(out, &cfg); err != nil {
		t.Fatalf("unmarshal config: %v", err)
	}
	return cfg.Apps.PKI.CertificateAuthorities
}

func TestParsePKIApp_skipInstallTrustHonoredForInternalTLSDefaultCA(t *testing.T) {
	input := `{
		auto_https off
		skip_install_trust
	}
	internal.example.com {
		tls internal
	}
	`
	cas := adaptedPKIConfig(t, input)

	ca, ok := cas["local"]
	if !ok {
		t.Fatal("expected certificate_authorities.local to exist")
	}
	if ca.InstallTrust == nil || *ca.InstallTrust != false {
		t.Errorf("install_trust = %v, want false", ca.InstallTrust)
	}
}

func TestParsePKIApp_skipInstallTrustHonoredForInternalTLSCustomCA(t *testing.T) {
	input := `{
		auto_https off
		skip_install_trust
	}
	internal.example.com {
		tls {
			issuer internal {
				ca mycustomca
			}
		}
	}
	`
	cas := adaptedPKIConfig(t, input)

	ca, ok := cas["mycustomca"]
	if !ok {
		t.Fatal("expected certificate_authorities.mycustomca to exist")
	}
	if ca.InstallTrust == nil || *ca.InstallTrust != false {
		t.Errorf("install_trust = %v, want false", ca.InstallTrust)
	}
}

func TestParsePKIApp_noPKIAppWhenNoInternalIssuerConfigured(t *testing.T) {
	input := `{
		auto_https off
		skip_install_trust
	}
	localhost:8080 {
		respond "no tls internal used anywhere"
	}
	`
	cas := adaptedPKIConfig(t, input)

	if len(cas) != 0 {
		t.Errorf("expected no certificate_authorities, got %v", cas)
	}
}

func TestParsePKIApp_renewalWindowRatioInvalid(t *testing.T) {
	input := `{
		pki {
			ca local {
				renewal_window_ratio 1.5
			}
		}
	}
	:8080 {
	}
	`
	adapter := caddyfile.Adapter{ServerType: ServerType{}}
	_, _, err := adapter.Adapt([]byte(input), nil)
	if err == nil {
		t.Error("expected error for renewal_window_ratio > 1")
	}
}
