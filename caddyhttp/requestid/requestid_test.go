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
	"testing"

	"github.com/google/uuid"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func TestRequestID(t *testing.T) {
	request, err := http.NewRequest("GET", "http://localhost/", nil)
	if err != nil {
		t.Fatal("Could not create HTTP request:", err)
	}

	reqid := uuid.New().String()

	c := context.WithValue(request.Context(), httpserver.RequestIDCtxKey, reqid)

	request = request.WithContext(c)

	// See caddyhttp/replacer.go
	value, _ := request.Context().Value(httpserver.RequestIDCtxKey).(string)

	if value == "" {
		t.Fatal("Request ID should not be empty")
	}

	if value != reqid {
		t.Fatal("Request ID does not match")
	}
}
