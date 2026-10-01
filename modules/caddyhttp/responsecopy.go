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

package caddyhttp

import (
	"context"
	"net/http"

	"github.com/caddyserver/caddy/v2"
)

// ResponseCopier replays the response a handle_response route is working
// with, for copy_response and copy_response_headers. reverse_proxy and
// intercept each provide one for their routes.
type ResponseCopier interface {
	// CopyResponseHeaders copies header fields from the intercepted
	// response into w, limited by include and exclude lists.
	CopyResponseHeaders(w http.ResponseWriter, include, exclude map[string]struct{})

	// CopyResponse writes the intercepted status (or statusCode when
	// non-zero) and body through w.
	CopyResponse(w http.ResponseWriter, r *http.Request, statusCode int) error
}

const responseCopierCtxKey caddy.CtxKey = "response_copier"

// WithResponseCopier returns a context carrying copier for handle_response routes.
func WithResponseCopier(ctx context.Context, copier ResponseCopier) context.Context {
	return context.WithValue(ctx, responseCopierCtxKey, copier)
}

// GetResponseCopier returns the copier carried by ctx, if any.
func GetResponseCopier(ctx context.Context) (ResponseCopier, bool) {
	copier, ok := ctx.Value(responseCopierCtxKey).(ResponseCopier)
	return copier, ok
}
