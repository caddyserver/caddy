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
				respond "I'm a coffee pot"
			}
		}
		reverse_proxy localhost:9082
	}

	http://localhost:9082 {
		respond "I'm a teapot"
	}
	`, "caddyfile")

	// the proxied response declares its own Content-Length, which must not
	// frame the body that the response handler writes instead
	tester.AssertGetResponse("http://localhost:9080/", 200, "I'm a coffee pot")
}

func TestInterceptKeepsOriginalBodyWhenResponseHasNone(t *testing.T) {
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
				header X-Intercepted yes
			}
		}
		reverse_proxy localhost:9082
	}

	http://localhost:9082 {
		respond "I'm a teapot"
	}
	`, "caddyfile")

	// the response handler writes no body, so the proxied body is kept
	r, _ := tester.AssertGetResponse("http://localhost:9080/", 200, "I'm a teapot")
	if r.Header.Get("X-Intercepted") != "yes" {
		t.Fatalf(`header "X-Intercepted" value is not "yes": %s`, r.Header.Get("X-Intercepted"))
	}
}

func TestInterceptKeepsOriginalContentLengthWhenResponseHasNoBody(t *testing.T) {
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

	// the response handler writes a status without a body, so the proxied body
	// is kept, and a HEAD request still reports the length it would send
	req, err := http.NewRequest(http.MethodHead, "http://localhost:9080/", nil)
	if err != nil {
		t.Fatalf("unable to create request: %v", err)
	}
	r := tester.AssertResponseCode(req, 503)
	defer r.Body.Close()
	if got := r.Header.Get("Content-Length"); got != "12" {
		t.Fatalf("expected the proxied response's Content-Length of 12, got %q", got)
	}
}
