package caddytls

import (
	"context"
	"encoding/pem"
	"os"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

func TestLeafFileLoader(t *testing.T) {
	fl := LeafFileLoader{Files: []string{"../../caddytest/leafcert.pem"}}
	fl.Provision(caddy.Context{Context: context.Background()})

	out, err := fl.LoadLeafCertificates()
	if err != nil {
		t.Errorf("Leaf certs file loading test failed: %v", err)
	}
	if len(out) != 1 {
		t.Errorf("Error loading leaf cert in memory struct")
		return
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: out[0].Raw})

	pemFileBytes, err := os.ReadFile("../../caddytest/leafcert.pem")
	if err != nil {
		t.Errorf("Unable to read the example certificate from the file")
	}

	// Remove /r because windows.
	pemFileString := strings.ReplaceAll(string(pemFileBytes), "\r\n", "\n")

	if string(pemBytes) != pemFileString {
		t.Errorf("Leaf Certificate File Loader: Failed to load the correct certificate")
	}
}
