// main.go
package main

import (
	"github.com/mholt/caddy/caddy/caddymain"
	"github.com/mholt/caddy/caddyhttp/httpserver"

	_ "github.com/fellou89/caddy-reauth"
	_ "github.com/startsmartlabs/caddy-awscloudwatch"
	_ "github.com/startsmartlabs/caddy-redis"
	_ "github.com/startsmartlabs/caddy-secrets"
	_ "github.com/startsmartlabs/caddy-transformrequest"
	_ "github.com/startsmartlabs/caddy-transformresponse"
)

var run = caddymain.Run // replaced for tests
func main() {
	httpserver.RegisterDevDirective("awscloudwatch", "root")
	httpserver.RegisterDevDirective("secrets", "awscloudwatch")
	httpserver.RegisterDevDirective("transformrequest", "")
	httpserver.RegisterDevDirective("redis", "")
	httpserver.RegisterDevDirective("transformresponse", "")
	run()
}
