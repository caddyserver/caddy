// +build cors all

package external

import (
	"github.com/captncraig/caddy-cors"
	"github.com/mholt/caddy/caddy"
)

func init() {
	caddy.ActivateDirective("cors", cors.Setup)
}
