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

import (
	"bytes"
	"testing"
)

func TestFormatWithWrapUnbracedSite(t *testing.T) {
	// eligible: wrapped
	in := "localhost\nroot * /srv\nfile_server\n"
	want := "localhost {\n\troot * /srv\n\tfile_server\n}\n"
	if got := string(FormatWithOptions([]byte(in), FormatOptions{WrapUnbracedSite: true})); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	// ineligible: unchanged from default formatting (no-op wrap)
	snip := "(s) {\n\trespond 200\n}\n"
	if got := string(FormatWithOptions([]byte(snip), FormatOptions{WrapUnbracedSite: true})); got != string(Format([]byte(snip))) {
		t.Errorf("snippet should be a no-op for WrapUnbracedSite; got %q", got)
	}
	// default (option off) never wraps
	if got := string(Format([]byte(in))); got != "localhost\nroot * /srv\nfile_server\n" {
		t.Errorf("default Format must not wrap; got %q", got)
	}
}

func TestWrapUnbracedSiteIdempotentAndSemantic(t *testing.T) {
	in := "localhost\nrespond 200\n"
	once := FormatWithOptions([]byte(in), FormatOptions{WrapUnbracedSite: true})
	twice := FormatWithOptions(once, FormatOptions{WrapUnbracedSite: true})
	if !bytes.Equal(once, twice) {
		t.Errorf("not idempotent:\n once=%q\ntwice=%q", once, twice)
	}
}

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
