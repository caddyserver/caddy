package setup

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/mholt/caddy/caddy/parse"
	"github.com/mholt/caddy/middleware"
	"github.com/mholt/caddy/server"
)

// Controller is given to the setup function of middlewares which
// gives them access to be able to read tokens and set config. Each
// virtualhost gets their own server config and dispenser.
type Controller struct {
	*server.Config
	parse.Dispenser

	// OncePerServerBlock is a function that executes f
	// exactly once per server block, no matter how many
	// hosts are associated with it. If it is the first
	// time, the function f is executed immediately
	// (not deferred) and may return an error which is
	// returned by OncePerServerBlock.
	OncePerServerBlock func(f func() error) error

	// ServerBlockIndex is the 0-based index of the
	// server block as it appeared in the input.
	ServerBlockIndex int

	// ServerBlockHostIndex is the 0-based index of this
	// host as it appeared in the input at the head of the
	// server block.
	ServerBlockHostIndex int

	// ServerBlockHosts is a list of hosts that are
	// associated with this server block. All these
	// hosts, consequently, share the same tokens.
	ServerBlockHosts []string

	// ServerBlockStorage is used by a directive's
	// setup function to persist state between all
	// the hosts on a server block.
	ServerBlockStorage interface{}
}

// NewTestController creates a new *Controller for
// the input specified, with a filename of "Testfile".
// The Config is bare, consisting only of a Root of cwd.
//
// Used primarily for testing but needs to be exported so
// add-ons can use this as a convenience. Does not initialize
// the server-block-related fields.
func NewTestController(input string) *Controller {
	return &Controller{
		Config: &server.Config{
			Root: ".",
		},
		Dispenser: parse.NewDispenser("Testfile", strings.NewReader(input)),
		OncePerServerBlock: func(f func() error) error {
			return f()
		},
	}
}

// EmptyNext is a no-op function that can be passed into
// middleware.Middleware functions so that the assignment
// to the Next field of the Handler can be tested.
//
// Used primarily for testing but needs to be exported so
// add-ons can use this as a convenience.
var EmptyNext = middleware.HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) {
	return 0, nil
})

// SameNext does a pointer comparison between next1 and next2.
//
// Used primarily for testing but needs to be exported so
// add-ons can use this as a convenience.
func SameNext(next1, next2 middleware.Handler) bool {
	return fmt.Sprintf("%v", next1) == fmt.Sprintf("%v", next2)
}
