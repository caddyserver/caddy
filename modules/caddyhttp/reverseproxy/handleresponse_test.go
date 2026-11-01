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

package reverseproxy

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// TestHandleResponseInvalidStatusCodeClosesBody verifies that when a
// handle_response status code does not evaluate to an integer, the
// upstream response body is closed instead of being leaked.
func TestHandleResponseInvalidStatusCodeClosesBody(t *testing.T) {
	body := &closeTrackingBody{Buffer: bytes.NewBufferString("from-upstream")}

	h := minimalHandler(0, &Upstream{Host: new(Host), Dial: "unused.invalid:80"})
	h.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Header:     make(http.Header),
			Body:       body,
			Request:    req,
		}, nil
	})
	h.HandleResponse = []caddyhttp.ResponseHandler{{
		StatusCode: caddyhttp.WeakString("not-a-number"),
	}}

	req := prepareTestRequest(httptest.NewRequest(http.MethodGet, "http://example.com/", nil))
	err := h.ServeHTTP(httptest.NewRecorder(), req, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		return nil
	}))
	if err == nil {
		t.Fatal("expected an error for a non-integer status code, got nil")
	}
	if !body.closed {
		t.Error("upstream response body was not closed")
	}
}
