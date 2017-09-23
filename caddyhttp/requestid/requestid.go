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

	"github.com/mholt/caddy/caddyhttp/httpserver"
	uuid "github.com/nu7hatch/gouuid"
)

// Handler is a middleware handler
type Handler struct {
	Next httpserver.Handler
}

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	reqid := UUID()
	c := context.WithValue(r.Context(), httpserver.RequestIDCtxKey, reqid)
	r = r.WithContext(c)

	return h.Next.ServeHTTP(w, r)
}

// UUID returns U4 UUID
func UUID() string {
	u4, err := uuid.NewV4()
	if err != nil {
		log.Printf("[ERROR] generating request ID: %v", err)
		return ""
	}

	return u4.String()
}
