// +build cors all

package external

import (
	cors "github.com/captncraig/cors/caddy"
	"github.com/mholt/caddy/caddy"
)

func init() {
	caddy.ActivateDirective("cors", cors.Setup)
}
