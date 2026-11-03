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

func TestRequestBodyPlaceholderRespectsMaxSizeInTemplate(t *testing.T) {
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

	res := tester.AssertResponseCode(newUnknownLengthPost(t, "abcdefghijklm"), http.StatusRequestEntityTooLarge)
	res.Body.Close()
}

func TestRequestBodyPlaceholderRespectsMaxSizeInVarsRegexp(t *testing.T) {
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
		@bigbody {
			vars_regexp {http.request.body} "^.{20}"
		}
		handle @bigbody {
			respond "the body was too long matched"
		}
		respond "no match"
	}
  `, "caddyfile")

	res := tester.AssertResponseCode(newUnknownLengthPost(t, "abcdefghijklmnopqrstuvwxyz"), http.StatusRequestEntityTooLarge)
	res.Body.Close()
}

func TestRequestBodyPlaceholderDirectRespondExpansion(t *testing.T) {
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
		respond "{http.request.body}"
	}
  `, "caddyfile")

	// direct placeholder consumers expand the sanitized request-body limit
	// marker to its text instead of failing the request with 413; only the
	// templates and vars matchers propagate the 413 status
	tester.AssertResponse(newUnknownLengthPost(t, "abcdefghijklm"), http.StatusOK, "request body: http: request body too large")
}

// newUnknownLengthPost sends no Content-Length, so the body gets past
// request_body's early check and max_size trips while handlers read it.
func newUnknownLengthPost(t *testing.T, body string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "http://localhost:9080/", bytes.NewBufferString(body))
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}
	req.ContentLength = -1
	return req
}
