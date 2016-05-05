package setup

import (
	"github.com/mholt/caddy/middleware"
	"github.com/mholt/caddy/middleware/pprof"
)

//PProf returns a new instance of a pprof handler. It accepts no arguments or options.
func PProf(c *Controller) (middleware.Middleware, error) {
	found := false
	for c.Next() {
		if found {
			return nil, c.Err("pprof can only be specified once")
		}
		if len(c.RemainingArgs()) != 0 {
			return nil, c.ArgErr()
		}
		if c.NextBlock() {
			return nil, c.ArgErr()
		}
		found = true
	}

	return func(next middleware.Handler) middleware.Handler {
		return &pprof.Handler{Next: next, Mux: pprof.NewMux()}
	}, nil
}
