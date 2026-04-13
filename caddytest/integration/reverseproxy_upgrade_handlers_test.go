package integration

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddytest"
)

func TestReverseProxyUpgradeWithEncode(t *testing.T) {
	tester := caddytest.NewTester(t)
	backend := newUpgradeEchoBackend(t)
	defer backend.Close()

	tester.InitServer(fmt.Sprintf(`
{
	admin localhost:2999
	http_port 9080
	https_port 9443
	grace_period 1ns
	skip_install_trust
}

localhost:9080 {
	route {
		encode gzip
		reverse_proxy %s
	}
}
`, backend.addr), "caddyfile")

	client := newUpgradedStreamClientWithHeaders(t, map[string]string{
		"Accept-Encoding": "gzip",
	})
	defer client.Close()

	if err := client.echo("encode-upgrade\n"); err != nil {
		t.Fatalf("upgraded stream echo through encode failed: %v", err)
	}
}

func TestReverseProxyUpgradeWithInterceptHandleResponse(t *testing.T) {
	tester := caddytest.NewTester(t)
	backend := newUpgradeEchoBackend(t)
	defer backend.Close()

	tester.InitServer(fmt.Sprintf(`
{
	admin localhost:2999
	http_port 9080
	https_port 9443
	grace_period 1ns
	skip_install_trust
}

localhost:9080 {
	route {
		intercept {
			@upgrade status 101
			handle_response @upgrade {
				respond "should-not-run"
			}
		}
		reverse_proxy %s
	}
}
`, backend.addr), "caddyfile")

	client := newUpgradedStreamClientWithHeaders(t, nil)
	defer client.Close()

	if err := client.echo("intercept-upgrade\n"); err != nil {
		t.Fatalf("upgraded stream echo through intercept failed: %v", err)
	}
}

func newUpgradedStreamClientWithHeaders(t *testing.T, extraHeaders map[string]string) *upgradedStreamClient {
	t.Helper()

	conn, err := net.DialTimeout("tcp", "127.0.0.1:9080", 5*time.Second)
	if err != nil {
		t.Fatalf("dialing caddy: %v", err)
	}

	requestLines := []string{
		"GET /upgrade HTTP/1.1",
		"Host: localhost:9080",
		"Connection: Upgrade",
		"Upgrade: stress-stream",
	}
	for k, v := range extraHeaders {
		requestLines = append(requestLines, k+": "+v)
	}
	requestLines = append(requestLines, "", "")

	if _, err := io.WriteString(conn, strings.Join(requestLines, "\r\n")); err != nil {
		_ = conn.Close()
		t.Fatalf("writing upgrade request: %v", err)
	}

	reader := bufio.NewReader(conn)
	tproto := textproto.NewReader(reader)
	statusLine, err := tproto.ReadLine()
	if err != nil {
		_ = conn.Close()
		t.Fatalf("reading upgrade status line: %v", err)
	}
	if !strings.Contains(statusLine, "101") {
		_ = conn.Close()
		t.Fatalf("unexpected upgrade status: %s", statusLine)
	}

	headers, err := tproto.ReadMIMEHeader()
	if err != nil {
		_ = conn.Close()
		t.Fatalf("reading upgrade headers: %v", err)
	}
	if !strings.EqualFold(headers.Get("Connection"), "Upgrade") {
		_ = conn.Close()
		t.Fatalf("unexpected upgrade response headers: %v", headers)
	}

	return &upgradedStreamClient{conn: conn, reader: reader}
}
