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
			name:             "with wildcard in automate",
			automateNames:    []string{"*.example.com"},
			expectedToManage: false,
		},
		{
			name:             "without wildcard in automate",
			automateNames:    []string{},
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
