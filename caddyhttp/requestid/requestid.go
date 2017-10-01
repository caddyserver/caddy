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

package requestid

import (
	"context"
	"net/http"

	"github.com/google/uuid"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

// Handler is a middleware handler
type Handler struct {
	Next httpserver.Handler
}

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	reqid := uuid.New().String()
	c := context.WithValue(r.Context(), httpserver.RequestIDCtxKey, reqid)
	r = r.WithContext(c)

	return h.Next.ServeHTTP(w, r)
}
