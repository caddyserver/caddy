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
	"github.com/caddyserver/caddy/v2"

	// This package is required for go-fuzz-build, so pin it here for
	// 'go mod vendor' to include it.
	_ "github.com/dvyukov/go-fuzz/go-fuzz-dep"
)

func FuzzReplacer(data []byte) (score int) {
	caddy.NewReplacer().ReplaceAll(string(data), "")
	return 0
}
