package integration

import (
	"net/http"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddytest"
)

func TestReverseProxyHealthCheck(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(`
	localhost:2020 {
		file_server browse
	}
	localhost:2021 {
		respond "ok"
	}
	http://localhost:2022 {
		reverse_proxy {
			to https://localhost:2020
	
			health_path /health
			health_port 2021
			health_interval 2s
			health_timeout 5s
		}
	}
  `, "caddyfile")

	req, err := http.NewRequest(http.MethodGet, "http://localhost:2022/", nil)
	if err != nil {
		t.Fail()
		return
	}
	time.Sleep(time.Second * 10)
	tester.AssertResponseCode(req, 200)
}
