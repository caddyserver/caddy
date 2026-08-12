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
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"

	"github.com/caddyserver/caddy/v2/caddytest"
)

func TestReverseProxyHTTP3RequestBodyToHTTP2Upstream(t *testing.T) {
	type observation struct {
		proto         string
		contentLength int64
		body          string
	}

	observations := make(chan observation, 2)
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		observations <- observation{
			proto:         r.Proto,
			contentLength: r.ContentLength,
			body:          string(body),
		}
		w.WriteHeader(http.StatusOK)
	}))
	origin.EnableHTTP2 = true
	origin.StartTLS()
	t.Cleanup(origin.Close)

	tester := caddytest.NewTester(t)
	tester.InitServer(fmt.Sprintf(`
	{
		"admin": {"listen": "localhost:2999"},
		"apps": {
			"http": {
				"grace_period": 1,
				"servers": {
					"h3_proxy": {
						"listen": [":9443"],
						"protocols": ["h3"],
						"automatic_https": {"disable": true},
						"tls_connection_policies": [
							{
								"match": {"sni": ["localhost"]},
								"certificate_selection": {"any_tag": ["h3_test"]}
							}
						],
						"routes": [{
							"handle": [{
								"handler": "reverse_proxy",
								"upstreams": [{"dial": %q}],
								"transport": {
									"protocol": "http",
									"versions": ["2"],
									"tls": {"insecure_skip_verify": true}
								}
							}]
						}]
					}
				}
			},
			"tls": {
				"certificates": {
					"load_files": [{
						"certificate": "/caddy.localhost.crt",
						"key": "/caddy.localhost.key",
						"tags": ["h3_test"]
					}]
				}
			}
		}
	}
	`, origin.Listener.Addr().String()), "json")

	h3Transport := &http3.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
	}
	t.Cleanup(func() {
		if err := h3Transport.Close(); err != nil {
			t.Errorf("closing HTTP/3 transport: %v", err)
		}
	})
	client := &http.Client{
		Transport: h3Transport,
		Timeout:   5 * time.Second,
	}

	t.Run("empty body", func(t *testing.T) {
		resp, err := client.Get("https://localhost:9443/")
		if err != nil {
			t.Fatalf("HTTP/3 GET: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusOK)
		}
		if resp.Proto != "HTTP/3.0" {
			t.Fatalf("client protocol: got %q, want HTTP/3.0", resp.Proto)
		}

		got := <-observations
		if got.proto != "HTTP/2.0" {
			t.Fatalf("upstream protocol: got %q, want HTTP/2.0", got.proto)
		}
		if got.contentLength != 0 {
			t.Fatalf("upstream content length: got %d, want 0", got.contentLength)
		}
		if got.body != "" {
			t.Fatalf("upstream body: got %q, want empty", got.body)
		}
	})

	t.Run("streaming body", func(t *testing.T) {
		const wantBody = "streamed body"
		req, err := http.NewRequest(http.MethodGet, "https://localhost:9443/", strings.NewReader(wantBody))
		if err != nil {
			t.Fatalf("creating HTTP/3 GET: %v", err)
		}
		req.ContentLength = -1

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("HTTP/3 GET: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusOK)
		}
		if resp.Proto != "HTTP/3.0" {
			t.Fatalf("client protocol: got %q, want HTTP/3.0", resp.Proto)
		}

		got := <-observations
		if got.proto != "HTTP/2.0" {
			t.Fatalf("upstream protocol: got %q, want HTTP/2.0", got.proto)
		}
		if got.contentLength != -1 {
			t.Fatalf("upstream content length: got %d, want -1", got.contentLength)
		}
		if got.body != wantBody {
			t.Fatalf("upstream body: got %q, want %q", got.body, wantBody)
		}
	})
}
