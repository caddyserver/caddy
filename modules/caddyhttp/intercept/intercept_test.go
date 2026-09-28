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

package intercept

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

const (
	originBody      = "I'm a teapot"
	replacementBody = "I'm a combined coffee/tea pot that is temporarily out of coffee"
)

// originResponse declares its own Content-Length, the way reverse_proxy and
// file_server do.
var originResponse caddyhttp.Handler = caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Content-Length", strconv.Itoa(len(originBody)))
	_, err := io.WriteString(w, originBody)
	return err
})

// replacementHandler starts the replacement response with before, then writes
// the body.
type replacementHandler struct {
	before func(w http.ResponseWriter) error
}

func (h replacementHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, _ caddyhttp.Handler) error {
	w.WriteHeader(http.StatusOK)
	if err := h.before(w); err != nil {
		return err
	}
	_, err := io.WriteString(w, replacementBody)
	return err
}

// A replacement response that opens with a flush or an empty write still has to
// drop the original Content-Length, or net/http aborts the body it frames.
func TestInterceptReplacementBodyAfterPartialWrite(t *testing.T) {
	for i, tc := range []struct {
		name   string
		before func(w http.ResponseWriter) error
	}{
		{
			name: "flush before the body",
			before: func(w http.ResponseWriter) error {
				return http.NewResponseController(w).Flush()
			},
		},
		{
			name: "empty write before the body",
			before: func(w http.ResponseWriter) error {
				_, err := w.Write(nil)
				return err
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
			defer cancel()

			route := caddyhttp.Route{
				Handlers: []caddyhttp.MiddlewareHandler{replacementHandler{before: tc.before}},
			}
			if err := route.ProvisionHandlers(ctx, nil); err != nil {
				t.Fatalf("Test %d: provisioning the response handler: %v", i, err)
			}

			ir := Intercept{
				HandleResponse: []caddyhttp.ResponseHandler{{Routes: caddyhttp.RouteList{route}}},
			}
			ir.logger = zap.NewNop()

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				r = r.WithContext(context.WithValue(r.Context(), caddy.ReplacerCtxKey, caddy.NewReplacer()))
				if err := ir.ServeHTTP(w, r, originResponse); err != nil {
					t.Errorf("Test %d: serving: %v", i, err)
				}
			}))
			defer srv.Close()

			resp, err := srv.Client().Get(srv.URL)
			if err != nil {
				t.Fatalf("Test %d: request failed: %v", i, err)
			}
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("Test %d: reading the replacement body: %v", i, err)
			}
			if string(body) != replacementBody {
				t.Errorf("Test %d: expected body %q, got %q", i, replacementBody, string(body))
			}
		})
	}
}
