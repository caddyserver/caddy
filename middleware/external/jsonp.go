// +build jsonp all

package external

import (
	"github.com/mholt/caddy/caddy"
	"github.com/pschlump/caddy-jsonp"
)

func init() {
	caddy.ActivateDirective("jsonp", jsonp.Setup)
}
