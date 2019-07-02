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

package expvar

import (
	"expvar"
	"fmt"
	"net/http"

	"github.com/caddyserver/caddy/caddyhttp/httpserver"
)

// ExpVar is a simple struct to hold expvar's configuration
type ExpVar struct {
	Next     httpserver.Handler
	Resource Resource
}

// ServeHTTP handles requests to expvar's configured entry point with
// expvar, or passes all other requests up the chain.
func (e ExpVar) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	if httpserver.Path(r.URL.Path).Matches(string(e.Resource)) {
		expvarHandler(w, r)
		return 0, nil
	}
	return e.Next.ServeHTTP(w, r)
}

// expvarHandler returns a JSON object will all the published variables.
//
// This is lifted straight from the expvar package.
func expvarHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	fmt.Fprintf(w, "{\n")
	first := true
	expvar.Do(func(kv expvar.KeyValue) {
		if !first {
			fmt.Fprintf(w, ",\n")
		}
		first = false
		fmt.Fprintf(w, "%q: %s", kv.Key, kv.Value)
	})
	fmt.Fprintf(w, "\n}\n")
}

// Resource contains the path to the expvar entry point
type Resource string
