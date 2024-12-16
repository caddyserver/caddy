package integration

import (
	"net/http"
	"testing"

	"github.com/caddyserver/caddy/v2/caddytest"
)

func TestAutoHTTPtoHTTPSRedirectsImplicitPort(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(`
	{
		admin localhost:2999
		skip_install_trust
		http_port     9080
		https_port    9443
	}
	localhost
	respond "Yahaha! You found me!"
  `, "caddyfile")

	tester.AssertRedirect("http://localhost:9080/", "https://localhost/", http.StatusPermanentRedirect)
}

func TestAutoHTTPtoHTTPSRedirectsExplicitPortSameAsHTTPSPort(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(`
	{
		skip_install_trust
		admin localhost:2999
		http_port     9080
		https_port    9443
	}
	localhost:9443
	respond "Yahaha! You found me!"
  `, "caddyfile")

	tester.AssertRedirect("http://localhost:9080/", "https://localhost/", http.StatusPermanentRedirect)
}

func TestAutoHTTPtoHTTPSRedirectsExplicitPortDifferentFromHTTPSPort(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(`
	{
		skip_install_trust
		admin localhost:2999
		http_port     9080
		https_port    9443
	}
	localhost:1234
	respond "Yahaha! You found me!"
  `, "caddyfile")

	tester.AssertRedirect("http://localhost:9080/", "https://localhost:1234/", http.StatusPermanentRedirect)
}

func TestAutoHTTPRedirectsWithHTTPListenerFirstInAddresses(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(`
{
  "admin": {
	"listen": "localhost:2999"
  },
  "apps": {
    "http": {
      "http_port": 9080,
      "https_port": 9443,
      "servers": {
        "ingress_server": {
          "listen": [
            ":9080",
            ":9443"
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
	tester.AssertRedirect("http://localhost:9080/", "https://localhost/", http.StatusPermanentRedirect)
}

func TestAutoHTTPRedirectsInsertedBeforeUserDefinedCatchAll(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(`
	{
		skip_install_trust
		admin localhost:2999
		http_port     9080
		https_port    9443
		local_certs
	}
	http://:9080 {
		respond "Foo"
	}
	http://baz.localhost:9080 {
		respond "Baz"
	}
	bar.localhost {
		respond "Bar"
	}
  `, "caddyfile")
	tester.AssertRedirect("http://bar.localhost:9080/", "https://bar.localhost/", http.StatusPermanentRedirect)
	tester.AssertGetResponse("http://foo.localhost:9080/", 200, "Foo")
	tester.AssertGetResponse("http://baz.localhost:9080/", 200, "Baz")
}

func TestAutoHTTPRedirectsInsertedBeforeUserDefinedCatchAllWithNoExplicitHTTPSite(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(`
	{
		skip_install_trust
		admin localhost:2999
		http_port     9080
		https_port    9443
		local_certs
	}
	http://:9080 {
		respond "Foo"
	}
	bar.localhost {
		respond "Bar"
	}
  `, "caddyfile")
	tester.AssertRedirect("http://bar.localhost:9080/", "https://bar.localhost/", http.StatusPermanentRedirect)
	tester.AssertGetResponse("http://foo.localhost:9080/", 200, "Foo")
	tester.AssertGetResponse("http://baz.localhost:9080/", 200, "Foo")
}
