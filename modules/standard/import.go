package standard

import (
	// standard Caddy modules
	_ "github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	_ "github.com/caddyserver/caddy/v2/caddyconfig/json5"
	_ "github.com/caddyserver/caddy/v2/caddyconfig/jsonc"
	_ "github.com/caddyserver/caddy/v2/modules/caddyhttp/standard"
	_ "github.com/caddyserver/caddy/v2/modules/caddypki"
	_ "github.com/caddyserver/caddy/v2/modules/caddytls"
	_ "github.com/caddyserver/caddy/v2/modules/caddytls/distributedstek"
	_ "github.com/caddyserver/caddy/v2/modules/caddytls/standardstek"
	_ "github.com/caddyserver/caddy/v2/modules/filestorage"
	_ "github.com/caddyserver/caddy/v2/modules/logging"
)
