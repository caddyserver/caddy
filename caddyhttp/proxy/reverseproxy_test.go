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
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
)

const (
	expectedResponse = "response from request proxied to upstream"
	expectedStatus   = http.StatusOK
)

var upstreamHost *httptest.Server

func setupTest() {
	upstreamHost = httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/test-path" {
				w.WriteHeader(expectedStatus)
				w.Write([]byte(expectedResponse))
			} else {
				w.WriteHeader(404)
				w.Write([]byte("Not found"))
			}
		}))
}

func tearDownTest() {
	upstreamHost.Close()
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

	rp := NewSingleHostReverseProxy(target, "", http.DefaultMaxIdleConnsPerHost)
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
