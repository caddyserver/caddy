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
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

func TestStatusCodeHandler(t *testing.T) {
	r := fakeRequest()
	w := httptest.NewRecorder()

	s := StatusCode{
		StatusCode: WeakString(strconv.Itoa(http.StatusNotFound)),
	}

	err := s.ServeHTTP(w, r, nil)
	if err != nil {
		t.Errorf("did not expect an error, but got: %v", err)
	}

	resp := w.Result()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected status %d but got %d", http.StatusNotFound, resp.StatusCode)
	}
}
