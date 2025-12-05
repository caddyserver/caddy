package integration

import (
	"bytes"
	"fmt"
	"net/http"
	"testing"

	"github.com/caddyserver/caddy/v2/caddytest"
)

func TestBrowse(t *testing.T) {
	harness := caddytest.StartHarness(t)
	harness.LoadConfig(`
	{
		skip_install_trust
		admin {$TESTING_CADDY_ADMIN_BIND}
		http_port     {$TESTING_CADDY_PORT_ONE}
		https_port    {$TESTING_CADDY_PORT_TWO}
		grace_period  1ns
	}
	http://localhost:{$TESTING_CADDY_PORT_ONE} {
		file_server browse
	}
  `, "caddyfile")

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://localhost:%d/", harness.Tester().PortOne()), nil)
	if err != nil {
		t.Fail()
		return
	}
	harness.AssertResponseCode(req, 200)
}

func TestRespondWithJSON(t *testing.T) {
	harness := caddytest.StartHarness(t)
	harness.LoadConfig(`
	{
		skip_install_trust
		admin {$TESTING_CADDY_ADMIN_BIND}
		http_port     {$TESTING_CADDY_PORT_ONE}
		https_port    {$TESTING_CADDY_PORT_TWO}
		grace_period  1ns
	}
	localhost {
		respond {http.request.body}
	}
  `, "caddyfile")

	res, _ := harness.AssertPostResponseBody(fmt.Sprintf("https://localhost:%d/", harness.Tester().PortTwo()),
		nil,
		bytes.NewBufferString(`{
		"greeting": "Hello, world!"
	}`), 200, `{
		"greeting": "Hello, world!"
	}`)
	if res.Header.Get("Content-Type") != "application/json" {
		t.Errorf("expected Content-Type to be application/json, but was %s", res.Header.Get("Content-Type"))
	}
}
