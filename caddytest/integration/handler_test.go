package integration

import (
	"bytes"
	"net/http"
	"testing"

	"github.com/caddyserver/caddy/v2/caddytest"
)

func TestBrowse(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(`
	{
		skip_install_trust
		admin localhost:2999
		http_port     9080
		https_port    9443
		grace_period  1ns
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

func TestRespondWithJSON(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(`
	{
		skip_install_trust
		admin localhost:2999
		http_port     9080
		https_port    9443
		grace_period  1ns
	}
	localhost {
		respond {http.request.body}
	}
  `, "caddyfile")

	res, _ := tester.AssertPostResponseBody("https://localhost:9443/",
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

func TestRequestBodyPlaceholderRespectsMaxSize(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(`
	{
		skip_install_trust
		admin localhost:2999
		http_port     9080
		https_port    9443
		grace_period  1ns
	}
	http://localhost:9080 {
		request_body {
			max_size 10
		}
		respond "{{placeholder \"http.request.body\"}}"
		templates
	}
  `, "caddyfile")

	req, err := http.NewRequest(http.MethodPost, "http://localhost:9080/", bytes.NewBufferString("abcdefghijklm"))
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}
	res := tester.AssertResponseCode(req, http.StatusRequestEntityTooLarge)
	res.Body.Close()
}
