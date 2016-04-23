package setup

import (
	"log"
	"strings"

	"github.com/mholt/caddy/middleware"
	"github.com/mholt/caddy/middleware/locale"
	"github.com/mholt/caddy/middleware/locale/method"
)

// Locale configures a new Locale middleware instance.
func Locale(c *Controller) (middleware.Middleware, error) {
	l, err := parseLocale(c)
	if err != nil {
		return nil, err
	}

	return func(next middleware.Handler) middleware.Handler {
		log.Printf("middle")
		l.Next = next
		return l
	}, nil
}

func parseLocale(c *Controller) (*locale.Locale, error) {
	result := &locale.Locale{
		AvailableLocales: []string{},
		Methods:          []method.Method{},
		Configuration: &method.Configuration{
			CookieName: "locale",
		},
	}

	for c.Next() {
		args := c.RemainingArgs()

		if len(args) > 0 {
			result.AvailableLocales = append(result.AvailableLocales, args...)
		}

		for c.NextBlock() {
			switch c.Val() {
			case "all":
				result.AvailableLocales = append(result.AvailableLocales, c.RemainingArgs()...)
			case "detect":
				detectArgs := c.RemainingArgs()
				if len(detectArgs) == 0 {
					return nil, c.ArgErr()
				}
				for _, detectArg := range detectArgs {
					method, found := method.Names[strings.ToLower(strings.TrimSpace(detectArg))]
					if !found {
						return nil, c.Errf("could not find detect method [%s]", detectArg)
					}
					result.Methods = append(result.Methods, method)
				}
			case "cookie":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				if value := strings.TrimSpace(c.Val()); value != "" {
					result.Configuration.CookieName = value
				}
			default:
				return nil, c.ArgErr()
			}
		}
	}

	if len(result.AvailableLocales) == 0 {
		return nil, c.Errf("no available locales specified")
	}

	if len(result.Methods) == 0 {
		result.Methods = append(result.Methods, method.Names["header"])
	}

	return result, nil
}
