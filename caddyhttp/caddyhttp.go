// Copyright 2015 Light Code Labs, LLC
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

package caddyhttp

import (
	// plug in the server
	_ "github.com/caddyserver/caddy/caddyhttp/httpserver"

	// plug in the standard directives
	_ "github.com/caddyserver/caddy/caddyhttp/basicauth"
	_ "github.com/caddyserver/caddy/caddyhttp/bind"
	_ "github.com/caddyserver/caddy/caddyhttp/browse"
	_ "github.com/caddyserver/caddy/caddyhttp/errors"
	_ "github.com/caddyserver/caddy/caddyhttp/expvar"
	_ "github.com/caddyserver/caddy/caddyhttp/extensions"
	_ "github.com/caddyserver/caddy/caddyhttp/fastcgi"
	_ "github.com/caddyserver/caddy/caddyhttp/gzip"
	_ "github.com/caddyserver/caddy/caddyhttp/header"
	_ "github.com/caddyserver/caddy/caddyhttp/index"
	_ "github.com/caddyserver/caddy/caddyhttp/internalsrv"
	_ "github.com/caddyserver/caddy/caddyhttp/limits"
	_ "github.com/caddyserver/caddy/caddyhttp/log"
	_ "github.com/caddyserver/caddy/caddyhttp/markdown"
	_ "github.com/caddyserver/caddy/caddyhttp/mime"
	_ "github.com/caddyserver/caddy/caddyhttp/pprof"
	_ "github.com/caddyserver/caddy/caddyhttp/proxy"
	_ "github.com/caddyserver/caddy/caddyhttp/push"
	_ "github.com/caddyserver/caddy/caddyhttp/redirect"
	_ "github.com/caddyserver/caddy/caddyhttp/requestid"
	_ "github.com/caddyserver/caddy/caddyhttp/rewrite"
	_ "github.com/caddyserver/caddy/caddyhttp/root"
	_ "github.com/caddyserver/caddy/caddyhttp/status"
	_ "github.com/caddyserver/caddy/caddyhttp/templates"
	_ "github.com/caddyserver/caddy/caddyhttp/timeouts"
	_ "github.com/caddyserver/caddy/caddyhttp/websocket"
	_ "github.com/caddyserver/caddy/onevent"
)
