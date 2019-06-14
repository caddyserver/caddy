package reverseproxy

import (
	"github.com/caddyserver/caddy"
)

// Register caddy module.
func init() {
	caddy.RegisterModule(caddy.Module{
		Name: "http.responders.reverse_proxy",
		New:  func() interface{} { return new(LoadBalanced) },
	})
}
