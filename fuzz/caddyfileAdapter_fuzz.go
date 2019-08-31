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
	"bytes"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"

	// This package is required for go-fuzz-build, so pin it here for
	// 'go mod vendor' to include it.
	_ "github.com/dvyukov/go-fuzz/go-fuzz-dep"
)

func FuzzCaddyfileAdapter(data []byte) int {
	adapter := caddyfile.Adapter{
		ServerType: httpcaddyfile.ServerType{},
	}
	b, warns, err := adapter.Adapt(data, nil)
	// Adapt func calls the Setup() func of the ServerType,
	// thus it's going across multiple layers, each can
	// return warnings or errors. Marking the presence of
	// errors or warnings as interesting in this case
	// could push the fuzzer towards a path where we only
	// catch errors. Let's push the fuzzer to where it passes
	// but breaks.
	if (err != nil) || (warns != nil && len(warns) > 0) {
		return 0
	}

	// adapted Caddyfile should be parseable by the configuration loader in admin.go
	err = caddy.Load(bytes.NewReader(b))
	if err != nil {
		return 0
	}
	return 1
}
