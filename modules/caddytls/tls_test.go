package caddytls

import (
	"net"
	"strings"
	"testing"
)

// TestHandleHTTPChallengeIPv6HostNormalization verifies the host normalization
// that HandleHTTPChallenge must apply before calling getAutomationPolicyForName
// and certmagic.GetACMEChallenge.
func TestHandleHTTPChallengeIPv6HostNormalization(t *testing.T) {
	tests := []struct {
		name      string
		rHost     string
		wantHost  string
	}{
		{
			name:     "IPv6 without port",
			rHost:    "[2a12:4944:efe4::]",
			wantHost: "2a12:4944:efe4::",
		},
		{
			name:     "IPv6 with port",
			rHost:    "[2a12:4944:efe4::]:80",
			wantHost: "2a12:4944:efe4::",
		},
		{
			name:     "IPv6 loopback without port",
			rHost:    "[::1]",
			wantHost: "::1",
		},
		{
			name:     "IPv6 loopback with port",
			rHost:    "[::1]:80",
			wantHost: "::1",
		},
		{
			name:     "IPv4 without port (no change expected)",
			rHost:    "192.0.2.1",
			wantHost: "192.0.2.1",
		},
		{
			name:     "IPv4 with port",
			rHost:    "192.0.2.1:80",
			wantHost: "192.0.2.1",
		},
		{
			name:     "domain without port (no change expected)",
			rHost:    "example.com",
			wantHost: "example.com",
		},
		{
			name:     "domain with port",
			rHost:    "example.com:80",
			wantHost: "example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _, err := net.SplitHostPort(tt.rHost)
			if err != nil {
				got = tt.rHost
				got = strings.TrimPrefix(got, "[")
				got = strings.TrimSuffix(got, "]")
			}

			if got != tt.wantHost {
				t.Errorf("normalized host = %q, want %q", got, tt.wantHost)
			}

			if strings.HasPrefix(tt.rHost, "[") {
				specificPolicy := &AutomationPolicy{subjects: []string{tt.wantHost}}
				defaultPolicy := &AutomationPolicy{}
				tlsApp := &TLS{
					Automation: &AutomationConfig{
						Policies:                        []*AutomationPolicy{specificPolicy},
						defaultPublicAutomationPolicy:   defaultPolicy,
						defaultInternalAutomationPolicy: defaultPolicy,
					},
				}

				// BUG: raw bracketed r.Host does not match the registered subject.
				if tlsApp.getAutomationPolicyForName(tt.rHost) == specificPolicy {
					t.Errorf("getAutomationPolicyForName(%q): should NOT match specific policy (demonstrates the bug)", tt.rHost)
				}
				// FIXED: normalized host correctly matches the registered subject.
				if tlsApp.getAutomationPolicyForName(tt.wantHost) != specificPolicy {
					t.Errorf("getAutomationPolicyForName(%q): should match specific policy", tt.wantHost)
				}
			}
		})
	}
}
