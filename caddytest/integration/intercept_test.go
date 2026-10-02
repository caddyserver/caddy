package integration

import (
	"net/http"
	"testing"

	"github.com/caddyserver/caddy/v2/caddytest"
)

func TestIntercept(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(`{
			skip_install_trust
			admin localhost:2999
			http_port     9080
			https_port    9443
			grace_period  1ns
		}
	
		localhost:9080 {
			respond /intercept "I'm a teapot" 408
			header /intercept To-Intercept ok
			respond /no-intercept "I'm not a teapot"

			intercept {
				@teapot status 408
				handle_response @teapot {
					header /intercept intercepted {resp.header.To-Intercept}
					respond /intercept "I'm a combined coffee/tea pot that is temporarily out of coffee" 503
				}
			}	
		}
		`, "caddyfile")

	r, _ := tester.AssertGetResponse("http://localhost:9080/intercept", 503, "I'm a combined coffee/tea pot that is temporarily out of coffee")
	if r.Header.Get("intercepted") != "ok" {
		t.Fatalf(`header "intercepted" value is not "ok": %s`, r.Header.Get("intercepted"))
	}

	tester.AssertGetResponse("http://localhost:9080/no-intercept", 200, "I'm not a teapot")
}

func TestInterceptReplaceStatusWithMatcher(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(`{
		skip_install_trust
		admin localhost:2999
		http_port     9080
		https_port    9443
		grace_period  1ns
	}

	localhost:9080 {
		respond /error "boom" 500

		intercept {
			@err status 5xx
			replace_status @err 200
		}
	}
	`, "caddyfile")

	tester.AssertGetResponse("http://localhost:9080/error", 200, "boom")
}

func TestInterceptReplaceStatusWithoutMatcher(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(`{
		skip_install_trust
		admin localhost:2999
		http_port     9080
		https_port    9443
		grace_period  1ns
	}

	localhost:9080 {
		respond /forbidden "denied" 403

		intercept {
			replace_status 200
		}
	}
	`, "caddyfile")

	tester.AssertGetResponse("http://localhost:9080/forbidden", 200, "denied")
}

func TestInterceptReplaceStatusNotMatched(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(`{
		skip_install_trust
		admin localhost:2999
		http_port     9080
		https_port    9443
		grace_period  1ns
	}

	localhost:9080 {
		respond /ok "all good" 200

		intercept {
			@err status 5xx
			replace_status @err 503
		}
	}
	`, "caddyfile")

	// 200 does not match @err (5xx), so status should pass through unchanged
	tester.AssertGetResponse("http://localhost:9080/ok", 200, "all good")
}

func TestInterceptHeaderOnlyMutationKeepsInterceptedResponse(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(`{
		skip_install_trust
		admin localhost:2999
		http_port     9080
		https_port    9443
		grace_period  1ns
	}

	localhost:9080 {
		intercept {
			handle_response {
				header X-Added added
				header X-Replace new
				header -X-Delete
			}
		}
		reverse_proxy localhost:9082
	}

	http://localhost:9082 {
		header X-Replace old
		header X-Delete gone
		respond "I'm a teapot"
	}
	`, "caddyfile")

	r, _ := tester.AssertGetResponse("http://localhost:9080/", 200, "I'm a teapot")
	if r.Header.Get("X-Added") != "added" {
		t.Fatalf(`header "X-Added" value is not "added": %s`, r.Header.Get("X-Added"))
	}
	if r.Header.Get("X-Replace") != "new" {
		t.Fatalf(`header "X-Replace" value is not "new": %s`, r.Header.Get("X-Replace"))
	}
	if r.Header.Get("X-Delete") != "" {
		t.Fatalf(`header "X-Delete" should be absent: %s`, r.Header.Get("X-Delete"))
	}
}

func TestInterceptHeaderOnlyMutationKeepsInterceptedRepresentation(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(`{
		skip_install_trust
		admin localhost:2999
		http_port     9080
		https_port    9443
		grace_period  1ns
	}

	localhost:9080 {
		intercept {
			handle_response {
				header Content-Length 5
				header Etag "\"new\""
			}
		}
		reverse_proxy localhost:9082
	}

	http://localhost:9082 {
		header Etag "\"abc\""
		respond "I'm a teapot"
	}
	`, "caddyfile")

	// the routes did not write this body, so its representation stays
	r, _ := tester.AssertGetResponse("http://localhost:9080/", 200, "I'm a teapot")
	if r.Header.Get("Content-Length") != "12" {
		t.Fatalf(`header "Content-Length" should stay 12 for the intercepted body: %s`, r.Header.Get("Content-Length"))
	}
	if r.Header.Get("Etag") != `"abc"` {
		t.Fatalf(`header "Etag" should stay the intercepted one: %s`, r.Header.Get("Etag"))
	}
}

func TestInterceptHeaderOnlyMutationKeepsDeletedRepresentation(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(`{
		skip_install_trust
		admin localhost:2999
		http_port     9080
		https_port    9443
		grace_period  1ns
	}

	localhost:9080 {
		intercept {
			handle_response {
				header -Etag
			}
		}
		reverse_proxy localhost:9082
	}

	http://localhost:9082 {
		header Etag "\"abc\""
		respond "I'm a teapot"
	}
	`, "caddyfile")

	r, _ := tester.AssertGetResponse("http://localhost:9080/", 200, "I'm a teapot")
	if r.Header.Get("Etag") != "" {
		t.Fatalf(`header "Etag" should stay deleted: %s`, r.Header.Get("Etag"))
	}
}

func TestInterceptHeaderOnlyMutationDropsAddedRepresentation(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(`{
		skip_install_trust
		admin localhost:2999
		http_port     9080
		https_port    9443
		grace_period  1ns
	}

	localhost:9080 {
		intercept {
			handle_response {
				header Etag "\"new\""
			}
		}
		reverse_proxy localhost:9082
	}

	http://localhost:9082 {
		respond "I'm a teapot"
	}
	`, "caddyfile")

	r, _ := tester.AssertGetResponse("http://localhost:9080/", 200, "I'm a teapot")
	if r.Header.Get("Etag") != "" {
		t.Fatalf(`header "Etag" should not describe the intercepted body: %s`, r.Header.Get("Etag"))
	}
}

func TestInterceptReplacementDropsUntouchedRepresentationHeaders(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(`{
		skip_install_trust
		admin localhost:2999
		http_port     9080
		https_port    9443
		grace_period  1ns
	}

	localhost:9080 {
		intercept {
			handle_response {
				respond "I'm a coffee pot"
			}
		}
		reverse_proxy localhost:9082
	}

	http://localhost:9082 {
		header Etag "\"abc\""
		header Last-Modified "Mon, 01 Jan 2024 00:00:00 GMT"
		header X-Frame-Options DENY
		respond "I'm a teapot"
	}
	`, "caddyfile")

	r, _ := tester.AssertGetResponse("http://localhost:9080/", 200, "I'm a coffee pot")
	if r.Header.Get("Etag") != "" {
		t.Fatalf(`header "Etag" should be absent: %s`, r.Header.Get("Etag"))
	}
	if r.Header.Get("Last-Modified") != "" {
		t.Fatalf(`header "Last-Modified" should be absent: %s`, r.Header.Get("Last-Modified"))
	}
	if r.Header.Get("X-Frame-Options") != "DENY" {
		t.Fatalf(`header "X-Frame-Options" value is not "DENY": %s`, r.Header.Get("X-Frame-Options"))
	}
}

func TestInterceptReplacementKeepsHeadersTheRouteSets(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(`{
		skip_install_trust
		admin localhost:2999
		http_port     9080
		https_port    9443
		grace_period  1ns
	}

	localhost:9080 {
		intercept {
			handle_response {
				header Etag "\"replacement\""
				respond "I'm a coffee pot"
			}
		}
		reverse_proxy localhost:9082
	}

	http://localhost:9082 {
		header Etag "\"abc\""
		header Last-Modified "Mon, 01 Jan 2024 00:00:00 GMT"
		header X-Frame-Options DENY
		respond "I'm a teapot"
	}
	`, "caddyfile")

	r, _ := tester.AssertGetResponse("http://localhost:9080/", 200, "I'm a coffee pot")
	if r.Header.Get("Etag") != `"replacement"` {
		t.Fatalf(`header "Etag" value is not "replacement": %s`, r.Header.Get("Etag"))
	}
}

func TestInterceptReplacementDropsSameValueRepresentationHeader(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(`{
		skip_install_trust
		admin localhost:2999
		http_port     9080
		https_port    9443
		grace_period  1ns
	}

	localhost:9080 {
		intercept {
			handle_response {
				header Etag "\"abc\""
				respond "I'm a coffee pot"
			}
		}
		reverse_proxy localhost:9082
	}

	http://localhost:9082 {
		header Etag "\"abc\""
		respond "I'm a teapot"
	}
	`, "caddyfile")

	// setting a representation field to the intercepted value is
	// indistinguishable from leaving it untouched, so it is dropped
	r, _ := tester.AssertGetResponse("http://localhost:9080/", 200, "I'm a coffee pot")
	if r.Header.Get("Etag") != "" {
		t.Fatalf(`header "Etag" set to the intercepted value should be dropped: %s`, r.Header.Get("Etag"))
	}
}

func TestInterceptCopyResponseHeadersSurvivesReplacement(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(`{
		skip_install_trust
		admin localhost:2999
		http_port     9080
		https_port    9443
		grace_period  1ns
	}

	localhost:9080 {
		intercept {
			handle_response {
				copy_response_headers
				respond "I'm a coffee pot"
			}
		}
		reverse_proxy localhost:9082
	}

	http://localhost:9082 {
		header Etag "\"abc\""
		header Last-Modified "Mon, 01 Jan 2024 00:00:00 GMT"
		header X-Frame-Options DENY
		respond "I'm a teapot"
	}
	`, "caddyfile")

	r, _ := tester.AssertGetResponse("http://localhost:9080/", 200, "I'm a coffee pot")
	if r.Header.Get("Etag") != `"abc"` {
		t.Fatalf(`header "Etag" value is not "abc": %s`, r.Header.Get("Etag"))
	}
	if r.Header.Get("Content-Length") == "12" {
		t.Fatalf("the intercepted Content-Length must not frame the replacement")
	}
}

func TestInterceptCopyResponseKeepsInterceptedRepresentation(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(`{
		skip_install_trust
		admin localhost:2999
		http_port     9080
		https_port    9443
		grace_period  1ns
	}

	localhost:9080 {
		intercept {
			handle_response {
				copy_response 201
			}
		}
		reverse_proxy localhost:9082
	}

	http://localhost:9082 {
		header Etag "\"abc\""
		header Content-Type application/json
		respond "I'm a teapot"
	}
	`, "caddyfile")

	r, _ := tester.AssertGetResponse("http://localhost:9080/", 201, "I'm a teapot")
	if r.Header.Get("Etag") != `"abc"` {
		t.Fatalf(`header "Etag" value is not "abc": %s`, r.Header.Get("Etag"))
	}
	if r.Header.Get("Content-Type") != "application/json" {
		t.Fatalf(`header "Content-Type" value is not "application/json": %s`, r.Header.Get("Content-Type"))
	}
}

func TestInterceptCopyResponseReplaysInterceptedResponse(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(`{
		skip_install_trust
		admin localhost:2999
		http_port     9080
		https_port    9443
		grace_period  1ns
	}

	localhost:9080 {
		intercept {
			handle_response {
				copy_response_headers
				copy_response
			}
		}
		reverse_proxy localhost:9082
	}

	http://localhost:9082 {
		header Etag "\"abc\""
		header Last-Modified "Mon, 01 Jan 2024 00:00:00 GMT"
		header X-Frame-Options DENY
		respond "I'm a teapot"
	}
	`, "caddyfile")

	r, _ := tester.AssertGetResponse("http://localhost:9080/", 200, "I'm a teapot")
	if r.Header.Get("Etag") != `"abc"` {
		t.Fatalf(`header "Etag" value is not "abc": %s`, r.Header.Get("Etag"))
	}
}

func TestInterceptStatusOnlyReplacementSendsEmptyBody(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(`{
		skip_install_trust
		admin localhost:2999
		http_port     9080
		https_port    9443
		grace_period  1ns
	}

	localhost:9080 {
		intercept {
			handle_response {
				respond "" 503
			}
		}
		reverse_proxy localhost:9082
	}

	http://localhost:9082 {
		respond "I'm a teapot"
	}
	`, "caddyfile")

	tester.AssertGetResponse("http://localhost:9080/", 503, "")

	tester.InitServer(`{
		skip_install_trust
		admin localhost:2999
		http_port     9080
		https_port    9443
		grace_period  1ns
	}

	localhost:9080 {
		intercept {
			handle_response {
				respond "" 204
			}
		}
		reverse_proxy localhost:9082
	}

	http://localhost:9082 {
		respond "I'm a teapot"
	}
	`, "caddyfile")

	tester.AssertGetResponse("http://localhost:9080/", 204, "")
}

func TestInterceptStatusOnlyNotModifiedSendsEmptyBody(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(`{
		skip_install_trust
		admin localhost:2999
		http_port     9080
		https_port    9443
		grace_period  1ns
	}

	localhost:9080 {
		intercept {
			handle_response {
				respond "" 304
			}
		}
		reverse_proxy localhost:9082
	}

	http://localhost:9082 {
		respond "I'm a teapot"
	}
	`, "caddyfile")

	tester.AssertGetResponse("http://localhost:9080/", 304, "")
}

func TestInterceptHeaderOnlyMutationKeepsContentLengthForHead(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(`{
		skip_install_trust
		admin localhost:2999
		http_port     9080
		https_port    9443
		grace_period  1ns
	}

	localhost:9080 {
		intercept {
			handle_response {
				header X-Added added
			}
		}
		reverse_proxy localhost:9082
	}

	http://localhost:9082 {
		respond "I'm a teapot"
	}
	`, "caddyfile")

	req, err := http.NewRequest(http.MethodHead, "http://localhost:9080/", nil)
	if err != nil {
		t.Fatalf("unable to create request %s", err)
	}
	r := tester.AssertResponseCode(req, 200)
	if r.Header.Get("Content-Length") != "12" {
		t.Fatalf(`header "Content-Length" value is not "12": %s`, r.Header.Get("Content-Length"))
	}
	if r.Header.Get("X-Added") != "added" {
		t.Fatalf(`header "X-Added" value is not "added": %s`, r.Header.Get("X-Added"))
	}
}

func TestInterceptHandlerErrorBeforeCommit(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(`{
		skip_install_trust
		admin localhost:2999
		http_port     9080
		https_port    9443
		grace_period  1ns
	}

	localhost:9080 {
		handle_errors {
			respond "oops" 500
		}
		intercept {
			handle_response {
				error 503
			}
		}
		reverse_proxy localhost:9082
	}

	http://localhost:9082 {
		respond "I'm a teapot"
	}
	`, "caddyfile")

	tester.AssertGetResponse("http://localhost:9080/", 500, "oops")
}

func TestInterceptReplacesBodyOfResponseWithContentLength(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(`{
		skip_install_trust
		admin localhost:2999
		http_port     9080
		https_port    9443
		grace_period  1ns
	}

	localhost:9080 {
		intercept {
			handle_response {
				respond "I'm a combined coffee/tea pot that is temporarily out of coffee"
			}
		}
		reverse_proxy localhost:9082
	}

	http://localhost:9082 {
		respond "I'm a teapot"
	}
	`, "caddyfile")

	tester.AssertGetResponse("http://localhost:9080/", 200, "I'm a combined coffee/tea pot that is temporarily out of coffee")
}
