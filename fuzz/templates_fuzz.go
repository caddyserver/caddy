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

// +build gofuzz
// +build gofuzz_libfuzzer

package fuzz

import (
	"bufio"
	"bytes"
	"net/http"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/templates"
	// This package is required for go-fuzz-build, so pin it here for
	// 'go mod vendor' to include it.
	_ "github.com/dvyukov/go-fuzz/go-fuzz-dep"
)

func FuzzTemplates(data []byte) int {
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(data)))
	if err != nil {
		return 0
	}
	t := &templates.Templates{}
	if err := t.ServeHTTP(
		&dummyWriter{header: make(http.Header)},
		req,
		caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
			return nil
		}),
	); err != nil {
		return 0
	}
	return 1
}

type dummyWriter struct {
	header http.Header
	code   int
}

func (w *dummyWriter) Header() http.Header {
	return w.header
}

func (w *dummyWriter) Write(data []byte) (int, error) {
	return len(data), nil
}

func (w *dummyWriter) WriteHeader(code int) {
	w.code = code
}
