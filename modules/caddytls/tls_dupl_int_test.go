package caddytls_test

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	_ "github.com/caddyserver/caddy/v2/modules/caddyhttp"
	_ "github.com/caddyserver/caddy/v2/modules/caddypki"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	_ "github.com/caddyserver/caddy/v2/modules/standard"
)

// TestIntegrationDuplicateAutomation tests that when a wildcard is present
// in the automate certificate loader and a concrete subdomain is discovered
// by the HTTP app, the concrete host is not individually managed. This test
// forces the HTTP app to start before the TLS app, reproducing the exact
// startup order that triggered the bug.
func TestIntegrationDuplicateAutomation(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
		return
	}
	config := fmt.Sprintf(`{
		"storage": {
			"module": "file_system",
			"root": "%s"
		},
		"apps": {
			"pki": {
				"certificate_authorities": {
					"local": {
						"install_trust": false
					}
				}
			},
			"http": {
				"http_port": 8080,
				"https_port": 8443,
				"servers": {
					"mre_server": {
						"listen": [":0"],
						"routes": [
							{
								"match": [{"host": ["sub.example.com"]}],
								"handle": [{"handler": "static_response", "body": "hello sub.example.com"}]
							}
						]
					}
				}
			},
			"tls": {
				"automation": {
					"policies": [
						{
							"issuers": [{"module": "internal"}]
						}
					]
				},
				"certificates": {
					"automate": ["*.example.com"]
				}
			}
		}
	}`, t.TempDir())

	var cfg caddy.Config
	if err := json.Unmarshal([]byte(config), &cfg); err != nil {
		t.Fatal(err)
	}

	// we cannot use caddytest since it uses a map internally,
	// which is the bug this test is meant to expose.
	rootCtx, err := caddy.ProvisionContext(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := caddy.NewContext(rootCtx)
	t.Cleanup(cancel)

	httpAppIface, err := ctx.App("http")
	if err != nil {
		t.Fatal(err)
	}
	tlsAppIface, err := ctx.App("tls")
	if err != nil {
		t.Fatal(err)
	}

	httpApp := httpAppIface.(caddy.App)
	tlsApp := tlsAppIface.(*caddytls.TLS)

	// Start HTTP app first. This will trigger Automatic HTTPS, which calls
	// tlsApp.Manage() for "sub.example.com".
	if err := httpApp.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { httpApp.Stop() })

	if tlsApp.IsManaging("sub.example.com") {
		t.Errorf("sub.example.com should NOT be individually managed; it should be covered by the wildcard in the automate loader")
	}

	if err := tlsApp.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tlsApp.Stop() })

	if tlsApp.IsManaging("sub.example.com") {
		t.Errorf("sub.example.com should NOT be individually managed after TLS app start")
	}

	if !tlsApp.IsManaging("*.example.com") {
		t.Errorf("*.example.com SHOULD be managed")
	}

	// to avoid timing issues, wait for the cert to be saved before cleanup.
	// otherwise, you get errors like the one below:
	// TempDir RemoveAll cleanup: unlinkat /tmp/xxxx: directory not empty
	obtained := false
	for i := 0; i < 20; i++ {
		if tlsApp.HasCertificateForSubject("*.example.com") {
			obtained = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if !obtained {
		t.Fatal("*.example.com certificate not obtained in time")
	}

}
