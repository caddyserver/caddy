package setup

import (
	"strings"

	"github.com/mholt/caddy/config/parse"
	"github.com/mholt/caddy/server"
)

// newTestController creates a new *Controller for
// the input specified, with a filename of "Testfile"
func newTestController(input string) *Controller {
	return Controller{
		Config:    &server.Config{},
		Dispenser: parse.NewDispenser("Testfile", strings.NewReader(input)),
	}
}
