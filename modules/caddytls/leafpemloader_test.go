package caddytls

import (
	"context"
	"encoding/pem"
	"os"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

func TestLeafPEMLoader(t *testing.T) {
	pl := LeafPEMLoader{Certificates: []string{`
-----BEGIN CERTIFICATE-----
MIICUTCCAfugAwIBAgIBADANBgkqhkiG9w0BAQQFADBXMQswCQYDVQQGEwJDTjEL
MAkGA1UECBMCUE4xCzAJBgNVBAcTAkNOMQswCQYDVQQKEwJPTjELMAkGA1UECxMC
VU4xFDASBgNVBAMTC0hlcm9uZyBZYW5nMB4XDTA1MDcxNTIxMTk0N1oXDTA1MDgx
NDIxMTk0N1owVzELMAkGA1UEBhMCQ04xCzAJBgNVBAgTAlBOMQswCQYDVQQHEwJD
TjELMAkGA1UEChMCT04xCzAJBgNVBAsTAlVOMRQwEgYDVQQDEwtIZXJvbmcgWWFu
ZzBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQCp5hnG7ogBhtlynpOS21cBewKE/B7j
V14qeyslnr26xZUsSVko36ZnhiaO/zbMOoRcKK9vEcgMtcLFuQTWDl3RAgMBAAGj
gbEwga4wHQYDVR0OBBYEFFXI70krXeQDxZgbaCQoR4jUDncEMH8GA1UdIwR4MHaA
FFXI70krXeQDxZgbaCQoR4jUDncEoVukWTBXMQswCQYDVQQGEwJDTjELMAkGA1UE
CBMCUE4xCzAJBgNVBAcTAkNOMQswCQYDVQQKEwJPTjELMAkGA1UECxMCVU4xFDAS
BgNVBAMTC0hlcm9uZyBZYW5nggEAMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEE
BQADQQA/ugzBrjjK9jcWnDVfGHlk3icNRq0oV7Ri32z/+HQX67aRfgZu7KWdI+Ju
Wm7DCfrPNGVwFWUQOmsPue9rZBgO
-----END CERTIFICATE-----
`}}
	pl.Provision(caddy.Context{Context: context.Background()})

	out, err := pl.LoadLeafCertificates()
	if err != nil {
		t.Errorf("Leaf certs pem loading test failed: %v", err)
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
		t.Errorf("Leaf Certificate Folder Loader: Failed to load the correct certificate")
	}
}
