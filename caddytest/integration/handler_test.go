package integration

import (
	"net/http"
	"testing"

	"github.com/caddyserver/caddy/v2/caddytest"
)

func TestBrowse(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(`
	{
		http_port     9080
		https_port    9443
	}
	http://localhost:9080 {
		file_server browse
	}
  `, "caddyfile")

	req, err := http.NewRequest(http.MethodGet, "http://localhost:9080/", nil)
	if err != nil {
		t.Fail()
		return
	}
	tester.AssertResponseCode(req, 200)
}
