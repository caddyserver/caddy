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
