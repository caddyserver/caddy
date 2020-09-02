package integration

import (
	"testing"

	"github.com/caddyserver/caddy/v2/caddytest"
)

func TestReverseProxyHealthCheck(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(`
	{
		http_port     9080
		https_port    9443
	}
	http://localhost:2020 {
		respond "Hello, World!"
	}
	http://localhost:2021 {
		respond "ok"
	}
	http://localhost:9080 {
		reverse_proxy {
			to localhost:2020
	
			health_path /health
			health_port 2021
			health_interval 2s
			health_timeout 5s
		}
	}
  `, "caddyfile")

	tester.AssertGetResponse("http://localhost:9080/", 200, "Hello, World!")
}
