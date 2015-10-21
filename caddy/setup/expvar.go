package setup

import (
	_ "expvar"

	"github.com/mholt/caddy/middleware"
	"github.com/mholt/caddy/middleware/expvar"
)

// ExpVar configures a new ExpVar middleware instance.
func ExpVar(c *Controller) (middleware.Middleware, error) {
	resource, err := expVarParse(c)
	if err != nil {
		return nil, err
	}

	expvar := expvar.ExpVar{Resource: resource}

	return func(next middleware.Handler) middleware.Handler {
		expvar.Next = next
		return expvar
	}, nil
}

func expVarParse(c *Controller) (expvar.Resource, error) {
	var resource expvar.Resource

	var err error
	for c.Next() {
		args := c.RemainingArgs()

		switch len(args) {
		case 1:
			resource = expvar.Resource(args[0])
		default:
			return resource, c.ArgErr()
		}
	}

	return resource, err
}
