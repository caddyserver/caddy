package reverseproxy

import (
	"github.com/caddyserver/caddy2"
)

// Register caddy module.
func init() {
	caddy2.RegisterModule(caddy2.Module{
		Name: "http.responders.reverse_proxy",
		New:  func() interface{} { return new(LoadBalanced) },
	})
}
