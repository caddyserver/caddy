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

// Most of the code in this file was initially borrowed from the Go
// standard library and modified; It had this copyright notice:
// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Original source, copied because the package was marked internal:
// https://github.com/golang/go/blob/5c489514bc5e61ad9b5b07bd7d8ec65d66a0512a/src/net/http/internal/ascii/print_test.go

package reverseproxy

import "testing"

func TestEqualFold(t *testing.T) {
	tests := []struct {
		name string
		a, b string
		want bool
	}{
		{
			name: "empty",
			want: true,
		},
		{
			name: "simple match",
			a:    "CHUNKED",
			b:    "chunked",
			want: true,
		},
		{
			name: "same string",
			a:    "chunked",
			b:    "chunked",
			want: true,
		},
		{
			name: "Unicode Kelvin symbol",
			a:    "chunKed", // This "K" is 'KELVIN SIGN' (\u212A)
			b:    "chunked",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := asciiEqualFold(tt.a, tt.b); got != tt.want {
				t.Errorf("AsciiEqualFold(%q,%q): got %v want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestIsPrint(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{
			name: "empty",
			want: true,
		},
		{
			name: "ASCII low",
			in:   "This is a space: ' '",
			want: true,
		},
		{
			name: "ASCII high",
			in:   "This is a tilde: '~'",
			want: true,
		},
		{
			name: "ASCII low non-print",
			in:   "This is a unit separator: \x1F",
			want: false,
		},
		{
			name: "Ascii high non-print",
			in:   "This is a Delete: \x7F",
			want: false,
		},
		{
			name: "Unicode letter",
			in:   "Today it's 280K outside: it's freezing!", // This "K" is 'KELVIN SIGN' (\u212A)
			want: false,
		},
		{
			name: "Unicode emoji",
			in:   "Gophers like 🧀",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := asciiIsPrint(tt.in); got != tt.want {
				t.Errorf("IsASCIIPrint(%q): got %v want %v", tt.in, got, tt.want)
			}
		})
	}
}
