package integration

import (
	"fmt"
	"testing"

	"github.com/caddyserver/caddy/v2/caddytest"
)

func TestIntercept(t *testing.T) {
	harness := caddytest.StartHarness(t)
	harness.LoadConfig(`{
			skip_install_trust
			admin {$TESTING_CADDY_ADMIN_BIND}
			http_port     {$TESTING_CADDY_PORT_ONE}
			https_port    {$TESTING_CADDY_PORT_TWO}
			grace_period  1ns
		}

		localhost:{$TESTING_CADDY_PORT_ONE} {
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

	r, _ := harness.AssertGetResponse(fmt.Sprintf("http://localhost:%d/intercept", harness.Tester().PortOne()), 503, "I'm a combined coffee/tea pot that is temporarily out of coffee")
	if r.Header.Get("intercepted") != "ok" {
		t.Fatalf(`header "intercepted" value is not "ok": %s`, r.Header.Get("intercepted"))
	}
	harness.AssertGetResponse(fmt.Sprintf("http://localhost:%d/no-intercept", harness.Tester().PortOne()), 200, "I'm not a teapot")
}
