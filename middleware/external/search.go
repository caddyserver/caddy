// +build search all

package external

import (
	"github.com/mholt/caddy/caddy"
	"github.com/pedronasser/caddy-search"
)

func init() {
	caddy.ActivateDirective("search", search.Setup)
}
