package integration

import (
	"net/http"
	"testing"

	"github.com/caddyserver/caddy/v2/caddytest"
)

func TestPlaceholderDefaults(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(`
 {
  admin localhost:2999
  http_port 9080
  grace_period 1ns
 }
 http://localhost:9080 {
  handle /literal {
   respond \{host}
  }
  header X-User "{cookie.session:-{header.X-User:-guest}}"
  respond "{cookie.session:-{header.X-User:-guest}}"
 }
 `, "caddyfile")
	tester.AssertGetResponse("http://localhost:9080/literal", http.StatusOK, "{host}")
	for _, tc := range []struct{ cookie, header, want string }{
		{want: "guest"},
		{header: "header-user", want: "header-user"},
		{cookie: "cookie-user", header: "header-user", want: "cookie-user"},
		{cookie: "{env.SECRET}", want: "{env.SECRET}"},
	} {
		req, err := http.NewRequest(http.MethodGet, "http://localhost:9080/", nil)
		if err != nil {
			t.Fatal(err)
		}
		if tc.cookie != "" {
			req.AddCookie(&http.Cookie{Name: "session", Value: tc.cookie})
		}
		if tc.header != "" {
			req.Header.Set("X-User", tc.header)
		}
		resp, _ := tester.AssertResponse(req, http.StatusOK, tc.want)
		if got := resp.Header.Get("X-User"); got != tc.want {
			t.Errorf("response header=%q; want %q", got, tc.want)
		}
	}
}
