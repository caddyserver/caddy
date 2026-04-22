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

package webtransport

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIsWebTransportUpgrade(t *testing.T) {
	cases := []struct {
		name  string
		proto string
		major int
		meth  string
		want  bool
	}{
		{"h3 connect webtransport", "webtransport", 3, http.MethodConnect, true},
		{"h3 connect websocket", "websocket", 3, http.MethodConnect, false},
		{"h2 connect webtransport", "webtransport", 2, http.MethodConnect, false},
		{"h3 GET", "HTTP/3.0", 3, http.MethodGet, false},
		{"h3 connect missing :protocol", "HTTP/3.0", 3, http.MethodConnect, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.meth, "/", nil)
			r.ProtoMajor = tc.major
			r.Proto = tc.proto
			if got := isWebTransportUpgrade(r); got != tc.want {
				t.Errorf("isWebTransportUpgrade = %v, want %v", got, tc.want)
			}
		})
	}
}

// nextNoop is a stand-in for the next handler. It records whether it was
// invoked, used to assert that non-WebTransport requests pass through.
type nextNoop struct{ called bool }

func (n *nextNoop) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	n.called = true
	return nil
}

func TestHandler_PassesThroughNonWebTransportRequests(t *testing.T) {
	h := &Handler{}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	nx := &nextNoop{}
	if err := h.ServeHTTP(w, r, nx); err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}
	if !nx.called {
		t.Error("expected next handler to be invoked for non-WebTransport request")
	}
}
