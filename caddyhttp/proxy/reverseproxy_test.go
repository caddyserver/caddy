// Copyright 2015 Light Code Labs, LLC
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

package proxy

import (
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/lucas-clemente/quic-go/http3"
)

const (
	expectedResponse = "response from request proxied to upstream"
	expectedStatus   = http.StatusOK
)

var upstreamHost *httptest.Server
var upstreamHostTLS *httptest.Server

func setupTLSServer() {
	upstreamHostTLS = httptest.NewTLSServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/test-path" {
				w.WriteHeader(expectedStatus)
				if _, err := w.Write([]byte(expectedResponse)); err != nil {
					log.Println("[ERROR] failed to write bytes: ", err)
				}
			} else {
				w.WriteHeader(404)
				if _, err := w.Write([]byte("Not found")); err != nil {
					log.Println("[ERROR] failed to write bytes: ", err)
				}
			}
		}))
}

func setupTest() {
	upstreamHost = httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/test-path" {
				w.WriteHeader(expectedStatus)
				if _, err := w.Write([]byte(expectedResponse)); err != nil {
					log.Println("[ERROR] failed to write bytes: ", err)
				}
			} else {
				w.WriteHeader(404)
				if _, err := w.Write([]byte("Not found")); err != nil {
					log.Println("[ERROR] failed to write bytes: ", err)
				}
			}
		}))
}

func tearDownTLSServer() {
	upstreamHostTLS.Close()
}

func tearDownTest() {
	upstreamHost.Close()
}

func TestReverseProxyWithOwnCACertificates(t *testing.T) {
	setupTLSServer()
	defer tearDownTLSServer()

	// get http client from tls server
	cl := upstreamHostTLS.Client()

	// add certs from httptest tls server to reverse proxy
	var transport *http.Transport
	if tr, ok := cl.Transport.(*http.Transport); ok {
		transport = tr
	} else {
		t.Error("could not parse transport from upstreamHostTLS")
	}

	pool := transport.TLSClientConfig.RootCAs

	u := staticUpstream{}
	u.CaCertPool = pool

	upstreamURL, err := url.Parse(upstreamHostTLS.URL)
	if err != nil {
		t.Errorf("Failed to parse test server URL [%s]. %s", upstreamHost.URL, err.Error())
	}

	// setup host for reverse proxy
	ups, err := u.NewHost(upstreamURL.String())
	if err != nil {
		t.Errorf("Creating new host failed. %v", err)
	}

	// UseOwnCACertificates called in NewHost sets the RootCAs based if the cert pool is set
	if transport, ok := ups.ReverseProxy.Transport.(*http.Transport); ok {
		if transport.TLSClientConfig.RootCAs == nil {
			t.Errorf("RootCAs not set on TLSClientConfig.")
		}
	} else if transport, ok := ups.ReverseProxy.Transport.(*http3.RoundTripper); ok {
		if transport.TLSClientConfig.RootCAs == nil {
			t.Errorf("RootCAs not set on TLSClientConfig.")
		}
	}

	resp := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "https://test.host/test-path", nil)
	if err != nil {
		t.Errorf("Failed to create new request. %s", err.Error())
	}

	err = ups.ReverseProxy.ServeHTTP(resp, req, nil)
	if err != nil {
		t.Errorf("Failed to perform reverse proxy to upstream host. %s", err.Error())
	}

	rBody := resp.Body.String()
	if rBody != expectedResponse {
		t.Errorf("Unexpected proxy response received. Expected: '%s', Got: '%s'", expectedResponse, resp.Body.String())
	}

	if resp.Code != expectedStatus {
		t.Errorf("Unexpected proxy status. Expected: '%d', Got: '%d'", expectedStatus, resp.Code)
	}
}
func TestSingleSRVHostReverseProxy(t *testing.T) {
	setupTest()
	defer tearDownTest()

	target, err := url.Parse("srv://test.upstream.service")
	if err != nil {
		t.Errorf("Failed to parse target URL. %s", err.Error())
	}

	upstream, err := url.Parse(upstreamHost.URL)
	if err != nil {
		t.Errorf("Failed to parse test server URL [%s]. %s", upstreamHost.URL, err.Error())
	}
	pp, err := strconv.Atoi(upstream.Port())
	if err != nil {
		t.Errorf("Failed to parse upstream server port [%s]. %s", upstream.Port(), err.Error())
	}
	port := uint16(pp)

	rp := NewSingleHostReverseProxy(target, "", http.DefaultMaxIdleConnsPerHost, 30*time.Second, 300*time.Millisecond)
	rp.srvResolver = testResolver{
		result: []*net.SRV{
			{Target: upstream.Hostname(), Port: port, Priority: 1, Weight: 1},
		},
	}

	resp := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "http://test.host/test-path", nil)
	if err != nil {
		t.Errorf("Failed to create new request. %s", err.Error())
	}

	err = rp.ServeHTTP(resp, req, nil)
	if err != nil {
		t.Errorf("Failed to perform reverse proxy to upstream host. %s", err.Error())
	}

	if resp.Body.String() != expectedResponse {
		t.Errorf("Unexpected proxy response received. Expected: '%s', Got: '%s'", expectedResponse, resp.Body.String())
	}

	if resp.Code != expectedStatus {
		t.Errorf("Unexpected proxy status. Expected: '%d', Got: '%d'", expectedStatus, resp.Code)
	}
}
