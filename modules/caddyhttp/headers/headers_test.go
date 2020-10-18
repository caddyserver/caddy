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

package headers

import (
	"context"
	"net/http"
	"reflect"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

func TestReqHeaders(t *testing.T) {
	// TODO: write tests
}

func TestHeaderOps(t *testing.T) {
	for i, tc := range []struct {
		headerOps HeaderOps
		input     http.Header
		expected  http.Header
	}{
		{
			headerOps: HeaderOps{
				Add: http.Header{
					"Expose-Secrets": []string{"always"},
				},
			},
			input: http.Header{
				"Expose-Secrets": []string{"i'm serious"},
			},
			expected: http.Header{
				"Expose-Secrets": []string{"i'm serious", "always"},
			},
		},
		{
			headerOps: HeaderOps{
				Set: http.Header{
					"Who-Wins": []string{"batman"},
				},
			},
			input: http.Header{
				"Who-Wins": []string{"joker"},
			},
			expected: http.Header{
				"Who-Wins": []string{"batman"},
			},
		},
		{
			headerOps: HeaderOps{
				SetDefault: http.Header{
					"Cache-Control": []string{"default"},
				},
			},
			input: http.Header{
				"Not-Cache-Control": []string{"cache-cache"},
			},
			expected: http.Header{
				"Cache-Control":     []string{"default"},
				"Not-Cache-Control": []string{"cache-cache"},
			},
		},
		{
			headerOps: HeaderOps{
				SetDefault: http.Header{
					"Cache-Control": []string{"no-store"},
				},
			},
			input: http.Header{
				"Cache-Control": []string{"max-age=3600"},
			},
			expected: http.Header{
				"Cache-Control": []string{"max-age=3600"},
			},
		},
		{
			headerOps: HeaderOps{
				Delete: []string{"Kick-Me"},
			},
			input: http.Header{
				"Kick-Me": []string{"if you can"},
				"Keep-Me": []string{"i swear i'm innocent"},
			},
			expected: http.Header{
				"Keep-Me": []string{"i swear i'm innocent"},
			},
		},
		{
			headerOps: HeaderOps{
				Replace: map[string][]Replacement{
					"Best-Server": []Replacement{
						Replacement{
							Search:  "NGINX",
							Replace: "the Caddy web server",
						},
						Replacement{
							SearchRegexp: `Apache(\d+)`,
							Replace:      "Caddy",
						},
					},
				},
			},
			input: http.Header{
				"Best-Server": []string{"it's NGINX, undoubtedly", "I love Apache2"},
			},
			expected: http.Header{
				"Best-Server": []string{"it's the Caddy web server, undoubtedly", "I love Caddy"},
			},
		},
	} {
		req := &http.Request{Header: tc.input}
		repl := caddy.NewReplacer()
		ctx := context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl)
		req = req.WithContext(ctx)

		tc.headerOps.Provision(caddy.Context{})
		tc.headerOps.ApplyToRequest(req)
		actual := req.Header

		if !reflect.DeepEqual(actual, tc.expected) {
			t.Errorf("Test %d: Expected %v, got %v", i, tc.expected, actual)
			continue
		}
	}
}
