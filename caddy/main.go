// main.go
package main
import (
	"github.com/mholt/caddy/caddy/caddymain"
	//_ "github.com/startsmartlabs/caddy-awscloudwatch"
	_ "github.com/startsmartlabs/caddy-redis"
	_ "github.com/startsmartlabs/caddy-secrets"
	_ "github.com/startsmartlabs/caddy-transformrequest"
	_ "github.com/startsmartlabs/caddy-transformresponse"
	_ "github.com/fellou89/caddy-reauth"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)
var run = caddymain.Run // replaced for tests
func main() {
	httpserver.RegisterDevDirective("secrets", "root")
	//httpserver.RegisterDevDirective("awscloudwatch", "root")
	httpserver.RegisterDevDirective("transformrequest", "")
	httpserver.RegisterDevDirective("redis", "")
	httpserver.RegisterDevDirective("transformresponse", "")
	run()
}