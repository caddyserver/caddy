// +build ipfilter all

package external

import (
	"github.com/mholt/caddy/caddy"
	"github.com/pyed/ipfilter"
)

func init() {
	caddy.ActivateDirective("ipfilter", ipfilter.Setup)
}
