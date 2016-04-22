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

	locales, methods, settings, err := localeParse(c)
	if err != nil {
		return nil, err
	}

	return func(next middleware.Handler) middleware.Handler {
		locale.Next = next
		locale.Locales = locales
		locale.Methods = methods
		locale.Settings = settings
		return locale
	}, nil
}

func localeParse(c *Controller) ([]string, []method.Method, *method.Settings, error) {
	locales := []string{}
	methods := []method.Method{}
	settings := &method.Settings{}

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
						return nil, nil, nil, c.ArgErr()
					}
					for _, detectArg := range detectArgs {
						method, found := method.Names[strings.ToLower(strings.TrimSpace(detectArg))]
						if !found {
							return nil, nil, nil, c.Errf("could not find detect method [%s]", detectArg)
						}
						methods = append(methods, method)
					}
				case "cookie":
					if !c.NextArg() {
						return nil, nil, nil, c.ArgErr()
					}
					settings.CookieName = c.Val()
				default:
					return nil, nil, nil, c.ArgErr()
				}
			}
		}
	}

	if len(locales) == 0 {
		return nil, nil, nil, c.Errf("no locales specified")
	}

	if len(methods) == 0 {
		methods = append(methods, method.Names["header"])
	}

	return locales, methods, settings, nil
}
