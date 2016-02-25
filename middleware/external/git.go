// +build git all

package external

import (
	"github.com/abiosoft/caddy-git"
	"github.com/mholt/caddy/caddy"
)

func init() {
	caddy.ActivateKnownDirective("git", git.Setup)
}
