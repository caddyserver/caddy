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
	"fmt"
	"net/http"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

func BenchmarkDynamicHeaderReplacement(b *testing.B) {
	for _, field := range []string{"Referer", "*"} {
		for _, count := range []int{1, 150} {
			b.Run(fmt.Sprintf("%s/values=%d", field, count), func(b *testing.B) {
				ops := &HeaderOps{Replace: map[string][]Replacement{
					field: {{SearchRegexp: "^https?://{host}/", Replace: "/"}},
				}}
				if err := ops.Provision(caddy.Context{}); err != nil {
					b.Fatal(err)
				}
				repl := caddy.NewReplacer()
				repl.Set("host", "example.test")
				hdr := http.Header{"Referer": make([]string, count)}
				b.ReportAllocs()
				for b.Loop() {
					for i := range hdr["Referer"] {
						hdr["Referer"][i] = "https://example.test/path"
					}
					ops.ApplyTo(hdr, repl)
				}
			})
		}
	}
}

func BenchmarkHeaderOpsApplyToSet(b *testing.B) {
	ops := &HeaderOps{
		Set: http.Header{
			"Content-Type":    []string{"text/html; charset=utf-8"},
			"Cache-Control":   []string{"public", "max-age=3600", "immutable"},
			"X-Custom-Header": []string{"value-one", "value-two"},
		},
	}
	repl := caddy.NewReplacer()
	b.ReportAllocs()
	for b.Loop() {
		hdr := make(http.Header)
		ops.ApplyTo(hdr, repl)
	}
}
