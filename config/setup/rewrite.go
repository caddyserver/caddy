package setup

import (
	"github.com/mholt/caddy/middleware"
	"github.com/mholt/caddy/middleware/rewrite"
)

// Rewrite configures a new Rewrite middleware instance.
func Rewrite(c *Controller) (middleware.Middleware, error) {
	rewrites, err := rewriteParse(c)
	if err != nil {
		return nil, err
	}

	return func(next middleware.Handler) middleware.Handler {
		return rewrite.Rewrite{Next: next, Rules: rewrites}
	}, nil
}

func rewriteParse(c *Controller) ([]rewrite.Rule, error) {
	var rewrites []rewrite.Rule

	for c.Next() {
		var rule rewrite.Rule

		if !c.NextArg() {
			return rewrites, c.ArgErr()
		}
		rule.From = c.Val()

		if !c.NextArg() {
			return rewrites, c.ArgErr()
		}
		rule.To = c.Val()

		rewrites = append(rewrites, rule)
	}

	return rewrites, nil
}
