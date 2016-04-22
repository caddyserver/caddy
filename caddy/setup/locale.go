package setup

import (
	"strings"

	"github.com/mholt/caddy/middleware"
	"github.com/mholt/caddy/middleware/locale"
	"github.com/mholt/caddy/middleware/locale/method"
)

// Locale configures a new Locale middleware instance.
func Locale(c *Controller) (middleware.Middleware, error) {
	locale := &locale.Locale{}

	locales, methods, err := localeParse(c)
	if err != nil {
		return nil, err
	}

	return func(next middleware.Handler) middleware.Handler {
		locale.Next = next
		locale.Locales = locales
		locale.Methods = methods
		return locale
	}, nil
}

func localeParse(c *Controller) ([]string, []method.Method, error) {
	locales := []string{}
	methods := []method.Method{&method.Header{}}

	for c.Next() {
		args := c.RemainingArgs()

		switch len(args) {
		default:
			locales = append(locales, args...)
			fallthrough
		case 0:
			for c.NextBlock() {
				switch c.Val() {
				case "all":
					locales = append(locales, c.RemainingArgs()...)
				case "detect":
					detectArgs := c.RemainingArgs()
					if len(detectArgs) == 0 {
						return nil, nil, c.ArgErr()
					}
					methods = []method.Method{}
					for _, detectArg := range detectArgs {
						method, found := method.Names[strings.ToLower(strings.TrimSpace(detectArg))]
						if !found {
							return nil, nil, c.ArgErr()
						}
						methods = append(methods, method)
					}
				default:
					return nil, nil, c.ArgErr()
				}
			}
		}
	}

	return locales, methods, nil
}
