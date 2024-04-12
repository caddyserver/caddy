package integration

import (
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
			respond /no-intercept "I'm not a teapot"

			intercept {
				@teapot status 408
				handle_response @teapot {
					respond /intercept "I'm a combined coffee/tea pot that is temporarily out of coffee" 503
				}
			}	
		}
		`, "caddyfile")

	tester.AssertGetResponse("http://localhost:9080/intercept", 503, "I'm a combined coffee/tea pot that is temporarily out of coffee")
	tester.AssertGetResponse("http://localhost:9080/no-intercept", 200, "I'm not a teapot")
}
