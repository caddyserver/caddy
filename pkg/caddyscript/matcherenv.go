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

package caddyscript

import (
	"net/http"

	caddyscript "github.com/caddyserver/caddy/v2/pkg/caddyscript/lib"
	"go.starlark.net/starlark"
)

// MatcherEnv sets up the global context for the matcher caddyscript environment.
func MatcherEnv(r *http.Request) starlark.StringDict {
	env := make(starlark.StringDict)
	env["req"] = caddyscript.HTTPRequest{Req: r}
	env["time"] = caddyscript.Time{}
	env["regexp"] = caddyscript.Regexp{}

	return env
}
