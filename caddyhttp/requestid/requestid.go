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
	"log"
	"net/http"

	"github.com/google/uuid"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

// Handler is a middleware handler
type Handler struct {
	Next       httpserver.Handler
	HeaderName string // (optional) header from which to read an existing ID
}

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	var reqid uuid.UUID

	uuidFromHeader := r.Header.Get(h.HeaderName)
	if h.HeaderName != "" && uuidFromHeader != "" {
		// use the ID in the header field if it exists
		var err error
		reqid, err = uuid.Parse(uuidFromHeader)
		if err != nil {
			log.Printf("[NOTICE] Parsing request ID from %s header: %v", h.HeaderName, err)
			reqid = uuid.New()
		}
	} else {
		// otherwise, create a new one
		reqid = uuid.New()
	}

	// set the request ID on the context
	c := context.WithValue(r.Context(), httpserver.RequestIDCtxKey, reqid.String())
	r = r.WithContext(c)

	return h.Next.ServeHTTP(w, r)
}
