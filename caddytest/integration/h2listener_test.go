package integration

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddytest"
)

func newH2ListenerWithVersionsWithTLSTester(t *testing.T, serverVersions []string, clientVersions []string) *caddytest.Tester {
	const baseConfig = `
	{
		skip_install_trust
		admin localhost:2999
		http_port     9080
		https_port    9443
		servers :9443 {
            protocols %s
        }
	}
	localhost {
		respond "{http.request.tls.proto} {http.request.proto}"
	}
	`
	tester := caddytest.NewTester(t)
	tester.InitServer(fmt.Sprintf(baseConfig, strings.Join(serverVersions, " ")), "caddyfile")

	tr := tester.Client.Transport.(*http.Transport)
	tr.TLSClientConfig.NextProtos = clientVersions
	tr.Protocols = new(http.Protocols)
	if slices.Contains(clientVersions, "h2") {
		tr.ForceAttemptHTTP2 = true
		tr.Protocols.SetHTTP2(true)
	}
	if !slices.Contains(clientVersions, "http/1.1") {
		tr.Protocols.SetHTTP1(false)
	}

	return tester
}

func TestH2ListenerWithTLS(t *testing.T) {
	tests := []struct {
		serverVersions []string
		clientVersions []string
		expectedBody   string
		failed         bool
	}{
		{[]string{"h2"}, []string{"h2"}, "h2 HTTP/2.0", false},
		{[]string{"h2"}, []string{"http/1.1"}, "", true},
		{[]string{"h1"}, []string{"http/1.1"}, "http/1.1 HTTP/1.1", false},
		{[]string{"h1"}, []string{"h2"}, "", true},
		{[]string{"h2", "h1"}, []string{"h2"}, "h2 HTTP/2.0", false},
		{[]string{"h2", "h1"}, []string{"http/1.1"}, "http/1.1 HTTP/1.1", false},
	}
	for _, tc := range tests {
		tester := newH2ListenerWithVersionsWithTLSTester(t, tc.serverVersions, tc.clientVersions)
		t.Logf("running with server versions %v and client versions %v:", tc.serverVersions, tc.clientVersions)
		if tc.failed {
			resp, err := tester.Client.Get("https://localhost:9443")
			if err == nil {
				t.Errorf("unexpected response: %d", resp.StatusCode)
			}
		} else {
			tester.AssertGetResponse("https://localhost:9443", 200, tc.expectedBody)
		}
	}
}

func newH2ListenerWithVersionsWithoutTLSTester(t *testing.T, serverVersions []string, clientVersions []string) *caddytest.Tester {
	const baseConfig = `
	{
		skip_install_trust
		admin localhost:2999
		http_port     9080
		servers :9080 {
            protocols %s
        }
	}
	http://localhost {
		respond "{http.request.proto}"
	}
	`
	tester := caddytest.NewTester(t)
	tester.InitServer(fmt.Sprintf(baseConfig, strings.Join(serverVersions, " ")), "caddyfile")

	tr := tester.Client.Transport.(*http.Transport)
	tr.Protocols = new(http.Protocols)
	if slices.Contains(clientVersions, "h2c") {
		tr.Protocols.SetHTTP1(false)
		tr.Protocols.SetUnencryptedHTTP2(true)
	} else if slices.Contains(clientVersions, "http/1.1") {
		tr.Protocols.SetHTTP1(true)
		tr.Protocols.SetUnencryptedHTTP2(false)
	}

	return tester
}

func TestH2ListenerWithoutTLS(t *testing.T) {
	tests := []struct {
		serverVersions []string
		clientVersions []string
		expectedBody   string
		failed         bool
	}{
		{[]string{"h2c"}, []string{"h2c"}, "HTTP/2.0", false},
		{[]string{"h2c"}, []string{"http/1.1"}, "", true},
		{[]string{"h1"}, []string{"http/1.1"}, "HTTP/1.1", false},
		{[]string{"h1"}, []string{"h2c"}, "", true},
		{[]string{"h2c", "h1"}, []string{"h2c"}, "HTTP/2.0", false},
		{[]string{"h2c", "h1"}, []string{"http/1.1"}, "HTTP/1.1", false},
	}
	for _, tc := range tests {
		tester := newH2ListenerWithVersionsWithoutTLSTester(t, tc.serverVersions, tc.clientVersions)
		t.Logf("running with server versions %v and client versions %v:", tc.serverVersions, tc.clientVersions)
		if tc.failed {
			resp, err := tester.Client.Get("http://localhost:9080")
			if err == nil {
				t.Errorf("unexpected response: %d", resp.StatusCode)
			}
		} else {
			tester.AssertGetResponse("http://localhost:9080", 200, tc.expectedBody)
		}
	}
}
