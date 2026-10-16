package caddytls

import (
	"testing"
)

// TestGetAutomationPolicyForNameNilAutomation ensures the getter is safe to
// call before Provision has initialized the automation config -- for example
// when the shared certificate cache's maintenance goroutine fires the
// GetConfigForCert callback during a config reload. A nil Automation used
// to cause a nil pointer dereference that leaked a cache read lock and hung
// reloads (issue #8231).
func TestGetAutomationPolicyForNameNilAutomation(t *testing.T) {
	for i, tc := range []struct {
		name   string
		tlsApp *TLS
	}{
		{"nil automation config", &TLS{}},
		// automation initialized but no policies provisioned yet: the
		// window between Automation initialization and policy provisioning
		{"automation without policies", &TLS{Automation: new(AutomationConfig)}},
	} {
		if ap := tc.tlsApp.getAutomationPolicyForName("example.com"); ap != nil {
			t.Errorf("Test %d (%s): expected nil automation policy, got %v", i, tc.name, ap)
		}
	}
}

// TestGetConfigForNameNilAutomation ensures getConfigForName returns a nil
// config (which certmagic handles as an ordinary error) instead of
// dereferencing a nil automation policy when Provision has not finished
// initializing (issue #8231).
func TestGetConfigForNameNilAutomation(t *testing.T) {
	for i, tc := range []struct {
		name   string
		tlsApp *TLS
	}{
		{"nil automation config", &TLS{}},
		{"automation without policies", &TLS{Automation: new(AutomationConfig)}},
	} {
		if cfg := tc.tlsApp.getConfigForName("example.com"); cfg != nil {
			t.Errorf("Test %d (%s): expected nil certmagic config, got %v", i, tc.name, cfg)
		}
	}
}
