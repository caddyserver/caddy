package setup

import (
	"github.com/mholt/caddy/middleware"
	"github.com/mholt/caddy/middleware/locale"
)

// Locale configures a new Locale middleware instance.
func Locale(c *Controller) (middleware.Middleware, error) {
	rootPath := c.Root
	locale := locale.Locale{}

	detectMethods, defaultLocale, err := localeParse(c)
	if err != nil {
		return nil, err
	}

	return func(next middleware.Handler) middleware.Handler {
		locale.Next = next
		locale.RootPath = rootPath
		locale.DetectMethods = detectMethods
		locale.DefaultLocale = defaultLocale
		return locale
	}, nil
}

func localeParse(c *Controller) ([]locale.DetectMethod, string, error) {
	detectMethods := []locale.DetectMethod{}
	defaultLocale := ""

	for c.Next() {
		args := c.RemainingArgs()
		if len(args) == 0 {
			return nil, "", c.Errf("no default locale specified")
		}

		for index := 0; index < len(args)-1; index++ {
			detectMethod, err := locale.ParseDetectMethod(args[index])
			if err != nil {
				return nil, "", c.Errf("error parsing detect method: %s", err)
			}
			detectMethods = append(detectMethods, detectMethod)
		}

		defaultLocale = args[len(args)-1]
	}

	return detectMethods, defaultLocale, nil
}
