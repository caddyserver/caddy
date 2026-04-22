// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package integration

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/webtransport-go"

	"github.com/caddyserver/caddy/v2/caddytest"
)

// TestWebTransport_EchoHandlerBidi spins up Caddy with an HTTP/3 listener
// that terminates a WebTransport session via the http.handlers.webtransport
// echo handler, then dials it with a real webtransport.Dialer and asserts
// an end-to-end bidirectional-stream round-trip. This exercises the
// serveH3AcceptLoop path (webtransport.Server.ServeQUICConn instead of
// http3.Server.ServeListener) and the UnwrapResponseWriterAs helper.
func TestWebTransport_EchoHandlerBidi(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	tester := caddytest.NewTester(t)
	tester.InitServer(`{
  "admin": {
    "listen": "localhost:2999"
  },
  "apps": {
    "http": {
      "http_port": 9080,
      "https_port": 9443,
      "grace_period": 1,
      "servers": {
        "srv0": {
          "listen": [":9443"],
          "protocols": ["h3"],
          "routes": [
            {
              "handle": [{"handler": "webtransport"}]
            }
          ],
          "tls_connection_policies": [
            {
              "certificate_selection": {"any_tag": ["cert0"]},
              "default_sni": "a.caddy.localhost"
            }
          ]
        }
      }
    },
    "tls": {
      "certificates": {
        "load_files": [
          {
            "certificate": "/a.caddy.localhost.crt",
            "key": "/a.caddy.localhost.key",
            "tags": ["cert0"]
          }
        ]
      }
    },
    "pki": {
      "certificate_authorities": {
        "local": {"install_trust": false}
      }
    }
  }
}`, "json")

	dialer := &webtransport.Dialer{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // test uses a local CA
			ServerName:         "a.caddy.localhost",
			NextProtos:         []string{http3.NextProtoH3},
		},
		QUICConfig: &quic.Config{
			EnableDatagrams:                  true,
			EnableStreamResetPartialDelivery: true,
		},
	}

	// Connect. Give the freshly-reconfigured server a brief window to be
	// ready on the UDP port; retry a handful of times instead of racing.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var (
		rsp  *http.Response
		sess *webtransport.Session
		err  error
	)
	deadline := time.Now().Add(3 * time.Second)
	for {
		rsp, sess, err = dialer.Dial(ctx, "https://127.0.0.1:9443/", nil)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("webtransport dial failed after retries: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	defer sess.CloseWithError(0, "")

	if rsp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %d", rsp.StatusCode)
	}

	// Open a bidirectional stream and send payload; expect it echoed back.
	str, err := sess.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}

	const payload = "hello webtransport"
	if _, err := io.WriteString(str, payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := str.Close(); err != nil {
		t.Fatalf("close send: %v", err)
	}

	got, err := io.ReadAll(str)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != payload {
		t.Fatalf("echo mismatch:\n  got:  %q\n  want: %q", strings.TrimSpace(string(got)), payload)
	}
}
