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

package limits

import (
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/caddyhttp/httpserver"
)

func TestBodySizeLimit(t *testing.T) {
	var (
		gotContent    []byte
		gotError      error
		expectContent = "hello"
	)
	l := Limit{
		Next: httpserver.HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) {
			gotContent, gotError = ioutil.ReadAll(r.Body)
			return 0, nil
		}),
		BodyLimits: []httpserver.PathLimit{{Path: "/", Limit: int64(len(expectContent))}},
	}

	r := httptest.NewRequest("GET", "/", strings.NewReader(expectContent+expectContent))
	if _, err := l.ServeHTTP(httptest.NewRecorder(), r); err != nil {
		log.Println("[ERROR] failed to serve HTTP: ", err)
	}
	if got := string(gotContent); got != expectContent {
		t.Errorf("expected content[%s], got[%s]", expectContent, got)
	}
	if gotError != httpserver.ErrMaxBytesExceeded {
		t.Errorf("expect error %v, got %v", httpserver.ErrMaxBytesExceeded, gotError)
	}
}
