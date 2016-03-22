package setup

import (
	stdexpvar "expvar"
	"runtime"
	"sync"

	"github.com/mholt/caddy/middleware"
	"github.com/mholt/caddy/middleware/expvar"
)

// ExpVar configures a new ExpVar middleware instance.
func ExpVar(c *Controller) (middleware.Middleware, error) {
	resource, err := expVarParse(c)
	if err != nil {
		return nil, err
	}

	// publish any extra information/metrics we may want to capture
	publishExtraVars()

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
		case 0:
			resource = expvar.Resource(defaultExpvarPath)
		case 1:
			resource = expvar.Resource(args[0])
		default:
			return resource, c.ArgErr()
		}
	}

	return resource, err
}

func publishExtraVars() {
	// By using sync.Once instead of an init() function, we don't clutter
	// the app's expvar export unnecessarily, or risk colliding with it.
	publishOnce.Do(func() {
		stdexpvar.Publish("Goroutines", stdexpvar.Func(func() interface{} {
			return runtime.NumGoroutine()
		}))
	})
}

var publishOnce sync.Once // publishing variables should only be done once
var defaultExpvarPath = "/debug/vars"
