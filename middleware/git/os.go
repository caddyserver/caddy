package git

import "github.com/mholt/caddy/middleware/git/gitos"

// gos is the OS used by git.
var gos gitos.OS = gitos.GitOS{}

// SetOS sets the OS to be used. Intended to be used for tests
// to abstract OS level git actions.
func SetOS(os gitos.OS) {
	gos = os
}
