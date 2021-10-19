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
	"fmt"
	"net/http"
	"strconv"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(CopyResponseHandler{})
}

// CopyResponseHandler is a special HTTP handler which may only be used
// within reverse_proxy's handle_response routes, to copy the response
// from the
type CopyResponseHandler struct {
	// To write the upstream response's body but with a different
	// status code, set this field to the desired status code.
	StatusCode caddyhttp.WeakString `json:"status_code,omitempty"`

	ctx caddy.Context
}

// CaddyModule returns the Caddy module information.
func (CopyResponseHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.copy_response",
		New: func() caddy.Module { return new(CopyResponseHandler) },
	}
}

// Provision ensures that h is set up properly before use.
func (h *CopyResponseHandler) Provision(ctx caddy.Context) error {
	h.ctx = ctx
	return nil
}

func (h CopyResponseHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request, _ caddyhttp.Handler) error {
	repl := req.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	hrc, ok := req.Context().Value(proxyHandleResponseContextCtxKey).(*handleResponseContext)

	// don't allow this to be used outside of handle_response routes
	if !ok {
		return caddyhttp.Error(http.StatusInternalServerError,
			fmt.Errorf("cannot use 'copy_response' outside of reverse_proxy's handle_response routes"))
	}

	// allow a custom status code to be written; otherwise the
	// status code from the upstream resposne is written
	if codeStr := h.StatusCode.String(); codeStr != "" {
		intVal, err := strconv.Atoi(repl.ReplaceAll(codeStr, ""))
		if err != nil {
			return caddyhttp.Error(http.StatusInternalServerError, err)
		}
		hrc.response.StatusCode = intVal
	}

	// make sure the reverse_proxy handler doesn't try to call
	// finalizeResponse again after we've already done it here.
	hrc.isFinalized = true

	// write the response
	return hrc.handler.finalizeResponse(rw, req, hrc.response, repl, hrc.start, hrc.logger, false)
}

// Interface guards
var (
	_ caddyhttp.MiddlewareHandler = (*CopyResponseHandler)(nil)
	_ caddyfile.Unmarshaler       = (*CopyResponseHandler)(nil)
)
