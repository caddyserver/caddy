package setup

import (
	"github.com/mholt/caddy/middleware"
	"github.com/mholt/caddy/middleware/locale"
	"github.com/mholt/caddy/middleware/locale/method"
)

// Locale configures a new Locale middleware instance.
func Locale(c *Controller) (middleware.Middleware, error) {
	rootPath := c.Root
	locale := &locale.Locale{}

	methods, defaultLocale, err := localeParse(c)
	if err != nil {
		return nil, err
	}

	return func(next middleware.Handler) middleware.Handler {
		locale.Next = next
		locale.RootPath = rootPath
		locale.Methods = methods
		locale.DefaultLocale = defaultLocale
		return locale
	}, nil
}

func localeParse(c *Controller) ([]method.Method, string, error) {
	methods := []method.Method{}
	defaultLocale := ""

	for c.Next() {
		args := c.RemainingArgs()
		if len(args) == 0 {
			return nil, "", c.Errf("no default locale specified")
		}

		for index := 0; index < len(args)-1; index++ {
			name := args[index]
			method, found := method.Names[name]
			if !found {
				return nil, "", c.Errf("unknown locale detect method [%s]", name)
			}
			methods = append(methods, method)
		}

		defaultLocale = args[len(args)-1]
	}

	return methods, defaultLocale, nil
}
