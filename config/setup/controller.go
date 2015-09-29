package setup

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/mholt/caddy/config/parse"
	"github.com/mholt/caddy/middleware"
	"github.com/mholt/caddy/server"
)

// Controller is given to the setup function of middlewares which
// gives them access to be able to read tokens and set config.
type Controller struct {
	*server.Config
	parse.Dispenser
}

// NewTestController creates a new *Controller for
// the input specified, with a filename of "Testfile"
//
// Used primarily for testing but needs to be exported so
// add-ons can use this as a convenience.
func NewTestController(input string) *Controller {
	return &Controller{
		Config:    &server.Config{},
		Dispenser: parse.NewDispenser("Testfile", strings.NewReader(input)),
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
