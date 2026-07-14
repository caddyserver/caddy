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

package caddyfile

import "testing"

func TestIsSingleUnbracedSite(t *testing.T) {
	yes := []string{
		"localhost\nrespond 200\n",
		"localhost\nreverse_proxy {\n\tto a:80\n}\n", // interior braces OK
	}
	no := []string{
		"localhost {\n\trespond 200\n}\n", // already braced
		"(snip) {\n\trespond 200\n}\n",    // snippet
		"&(route) {\n\trespond 200\n}\n",  // named route
		"{\n\tdebug\n}\n",                 // global options only
		"a.com\nrespond 200\n\nb.com\nrespond 404\n", // multi-site (ambiguous)
		"", // empty
	}
	for _, in := range yes {
		toks, _ := Lex([]byte(in), "", LexOptions{Comments: true, Raw: true})
		if !isSingleUnbracedSite(toks) {
			t.Errorf("want single-unbraced-site for %q", in)
		}
	}
	for _, in := range no {
		toks, _ := Lex([]byte(in), "", LexOptions{Comments: true, Raw: true})
		if isSingleUnbracedSite(toks) {
			t.Errorf("did NOT expect single-unbraced-site for %q", in)
		}
	}
}
