package integration

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/caddyserver/caddy/v2/caddytest"
)

func TestAutoHTTPtoHTTPSRedirectsImplicitPort(t *testing.T) {
	harness := caddytest.StartHarness(t)
	harness.LoadConfig(`
	{
		admin {$TESTING_CADDY_ADMIN_BIND}
		skip_install_trust
		http_port     {$TESTING_CADDY_PORT_ONE}
		https_port    {$TESTING_CADDY_PORT_TWO}
	}
	localhost
	respond "Yahaha! You found me!"
  `, "caddyfile")

	harness.AssertRedirect(fmt.Sprintf("http://localhost:%d/", harness.Tester().PortOne()), "https://localhost/", http.StatusPermanentRedirect)
}

func TestAutoHTTPtoHTTPSRedirectsExplicitPortSameAsHTTPSPort(t *testing.T) {
	harness := caddytest.StartHarness(t)
	harness.LoadConfig(`
	{
		skip_install_trust
		admin {$TESTING_CADDY_ADMIN_BIND}
		http_port     {$TESTING_CADDY_PORT_ONE}
		https_port    {$TESTING_CADDY_PORT_TWO}
	}
	localhost:{$TESTING_CADDY_PORT_TWO}
	respond "Yahaha! You found me!"
  `, "caddyfile")

	harness.AssertRedirect(fmt.Sprintf("http://localhost:%d/", harness.Tester().PortOne()), "https://localhost/", http.StatusPermanentRedirect)
}

func TestAutoHTTPtoHTTPSRedirectsExplicitPortDifferentFromHTTPSPort(t *testing.T) {
	harness := caddytest.StartHarness(t)
	harness.LoadConfig(`
	{
		skip_install_trust
		admin {$TESTING_CADDY_ADMIN_BIND}
		http_port     {$TESTING_CADDY_PORT_ONE}
		https_port    {$TESTING_CADDY_PORT_TWO}
	}
	localhost:1234
	respond "Yahaha! You found me!"
  `, "caddyfile")

	harness.AssertRedirect(fmt.Sprintf("http://localhost:%d/", harness.Tester().PortOne()), "https://localhost:1234/", http.StatusPermanentRedirect)
}

func TestAutoHTTPRedirectsWithHTTPListenerFirstInAddresses(t *testing.T) {
	harness := caddytest.StartHarness(t)
	harness.LoadConfig(`
{
  "admin": {
	"listen": "{$TESTING_CADDY_ADMIN_BIND}"
  },
  "apps": {
    "http": {
      "http_port": {$TESTING_CADDY_PORT_ONE},
      "https_port": {$TESTING_CADDY_PORT_TWO},
      "servers": {
        "ingress_server": {
          "listen": [
            ":{$TESTING_CADDY_PORT_ONE}",
            ":{$TESTING_CADDY_PORT_TWO}"
          ],
          "routes": [
            {
              "match": [
                {
				  "host": ["localhost"]
                }
              ]
            }
          ]
        }
      }
    },
	"pki": {
		"certificate_authorities": {
			"local": {
				"install_trust": false
			}
		}
	}
  }
}
`, "json")
	harness.AssertRedirect(fmt.Sprintf("http://localhost:%d/", harness.Tester().PortOne()), "https://localhost/", http.StatusPermanentRedirect)
}

func TestAutoHTTPRedirectsInsertedBeforeUserDefinedCatchAll(t *testing.T) {
	harness := caddytest.StartHarness(t)
	harness.LoadConfig(`
	{
		skip_install_trust
		admin {$TESTING_CADDY_ADMIN_BIND}
		http_port     {$TESTING_CADDY_PORT_ONE}
		https_port    {$TESTING_CADDY_PORT_TWO}
		local_certs
	}
	http://:{$TESTING_CADDY_PORT_ONE} {
		respond "Foo"
	}
	http://baz.localhost:{$TESTING_CADDY_PORT_ONE} {
		respond "Baz"
	}
	bar.localhost {
		respond "Bar"
	}
  `, "caddyfile")
	harness.AssertRedirect(fmt.Sprintf("http://bar.localhost:%d/", harness.Tester().PortOne()), "https://bar.localhost/", http.StatusPermanentRedirect)
	harness.AssertGetResponse(fmt.Sprintf("http://foo.localhost:%d/", harness.Tester().PortOne()), 200, "Foo")
	harness.AssertGetResponse(fmt.Sprintf("http://baz.localhost:%d/", harness.Tester().PortOne()), 200, "Baz")
}

func TestAutoHTTPRedirectsInsertedBeforeUserDefinedCatchAllWithNoExplicitHTTPSite(t *testing.T) {
	harness := caddytest.StartHarness(t)
	harness.LoadConfig(`
	{
		skip_install_trust
		admin {$TESTING_CADDY_ADMIN_BIND}
		http_port     {$TESTING_CADDY_PORT_ONE}
		https_port    {$TESTING_CADDY_PORT_TWO}
		local_certs
	}
	http://:{$TESTING_CADDY_PORT_ONE} {
		respond "Foo"
	}
	bar.localhost {
		respond "Bar"
	}
  `, "caddyfile")
	harness.AssertRedirect(fmt.Sprintf("http://bar.localhost:%d/", harness.Tester().PortOne()), "https://bar.localhost/", http.StatusPermanentRedirect)
	harness.AssertGetResponse(fmt.Sprintf("http://foo.localhost:%d/", harness.Tester().PortOne()), 200, "Foo")
	harness.AssertGetResponse(fmt.Sprintf("http://baz.localhost:%d/", harness.Tester().PortOne()), 200, "Foo")
}
