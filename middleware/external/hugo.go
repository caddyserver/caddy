// +build hugo all

package external

import (
	"github.com/hacdias/caddy-hugo"
	"github.com/mholt/caddy/caddy"
)

func init() {
	caddy.ActivateDirective("hugo", hugo.Setup)
}
