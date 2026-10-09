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
	"encoding/json"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

func TestAvoidDuplicateAutomation(t *testing.T) {
	tests := []struct {
		name             string
		automateNames    []string
		expectedToManage bool
	}{
		{
			name:             "do not manage if wildcard is automated",
			automateNames:    []string{"*.example.com"},
			expectedToManage: false,
		},
		{
			name:             "manage if no automation configured",
			automateNames:    []string{},
			expectedToManage: true,
		},
		{
			name:             "manage if explicitly requested even when wildcard automated",
			automateNames:    []string{"*.example.com", "sub.example.com"},
			expectedToManage: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			automateJSON, err := json.Marshal(tc.automateNames)
			if err != nil {
				t.Fatal(err)
			}

			tlsApp := &TLS{
				Automation: &AutomationConfig{
					Policies: []*AutomationPolicy{
						{
							IssuersRaw: []json.RawMessage{
								[]byte(`{"module": "internal"}`),
							},
						},
					},
				},
				CertificatesRaw: map[string]json.RawMessage{
					"automate": automateJSON,
				},
			}

			var cfg caddy.Config
			ctx, err := caddy.ProvisionContext(&cfg)
			if err != nil {
				t.Fatal(err)
			}

			if err := tlsApp.Provision(ctx); err != nil {
				t.Fatal(err)
			}

			// simulate a case wherein the HTTP app starts first and
			// tells the TLS app about the following auto-HTTPS domains
			httpDomains := map[string]struct{}{"sub.example.com": {}}
			if err := tlsApp.Manage(httpDomains); err != nil {
				t.Fatal(err)
			}

			_, actuallyManaged := tlsApp.managing["sub.example.com"]
			if actuallyManaged != tc.expectedToManage {
				t.Errorf(
					"expected sub.example.com individually managed: %v, got: %v",
					tc.expectedToManage,
					actuallyManaged,
				)
			}
		})
	}
}
