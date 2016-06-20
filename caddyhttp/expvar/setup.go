package expvar

import (
	"expvar"
	"runtime"
	"sync"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func init() {
	caddy.RegisterPlugin("expvar", caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	})
}

// setup configures a new ExpVar middleware instance.
func setup(c *caddy.Controller) error {
	resource, err := expVarParse(c)
	if err != nil {
		return err
	}

	// publish any extra information/metrics we may want to capture
	publishExtraVars()

	ev := ExpVar{Resource: resource}

	httpserver.GetConfig(c).AddMiddleware(func(next httpserver.Handler) httpserver.Handler {
		ev.Next = next
		return ev
	})

	return nil
}

func expVarParse(c *caddy.Controller) (Resource, error) {
	var resource Resource
	var err error

	for c.Next() {
		args := c.RemainingArgs()
		switch len(args) {
		case 0:
			resource = Resource(defaultExpvarPath)
		case 1:
			resource = Resource(args[0])
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
		expvar.Publish("Goroutines", expvar.Func(func() interface{} {
			return runtime.NumGoroutine()
		}))
	})
}

var publishOnce sync.Once // publishing variables should only be done once
var defaultExpvarPath = "/debug/vars"
