package integration

import (
	"net/http"
	"testing"

	"github.com/caddyserver/caddy/v2/caddytest"
)

func TestAutoHTTPtoHTTPSRedirects(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(`
	{
		http_port     9080
		https_port    9443
	}
	localhost:9443
	respond "Yahaha! You found me!"
  `, "caddyfile")

	tester.AssertRedirect("http://localhost:9080/", "https://localhost/", http.StatusPermanentRedirect)
}
