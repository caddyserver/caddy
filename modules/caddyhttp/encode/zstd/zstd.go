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

package caddyzstd

import (
	"github.com/caddyserver/caddy"
	"github.com/caddyserver/caddy/modules/caddyhttp/encode"
	"github.com/klauspost/compress/zstd"
)

func init() {
	caddy.RegisterModule(caddy.Module{
		Name: "http.encoders.zstd",
		New:  func() interface{} { return new(Zstd) },
	})
}

// Zstd can create zstd encoders.
type Zstd struct{}

// AcceptEncoding returns the name of the encoding as
// used in the Accept-Encoding request headers.
func (Zstd) AcceptEncoding() string { return "zstd" }

// NewEncoder returns a new gzip writer.
func (z Zstd) NewEncoder() encode.Encoder {
	writer, _ := zstd.NewWriter(nil)
	return writer
}

// Interface guard
var _ encode.Encoding = (*Zstd)(nil)
