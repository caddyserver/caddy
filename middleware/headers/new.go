package headers

import "github.com/mholt/caddy/middleware"

// New constructs and configures a new headers middleware instance.
func New(c middleware.Controller) (middleware.Middleware, error) {

	rules, err := parse(c)
	if err != nil {
		return nil, err
	}

	return func(next middleware.Handler) middleware.Handler {
		return Headers{Next: next, Rules: rules}
	}, nil
}
