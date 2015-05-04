package setup

import (
	"github.com/mholt/caddy/middleware"
	"github.com/mholt/caddy/middleware/basicauth"
)

// BasicAuth configures a new BasicAuth middleware instance.
func BasicAuth(c *Controller) (middleware.Middleware, error) {
	rules, err := basicAuthParse(c)
	if err != nil {
		return nil, err
	}

	basic := basicauth.BasicAuth{Rules: rules}

	return func(next middleware.Handler) middleware.Handler {
		basic.Next = next
		return basic
	}, nil
}

func basicAuthParse(c *Controller) ([]basicauth.Rule, error) {
	var rules []basicauth.Rule

	for c.Next() {
		var rule basicauth.Rule

		args := c.RemainingArgs()

		switch len(args) {
		case 2:
			rule.Username = args[0]
			rule.Password = args[1]
			for c.NextBlock() {
				rule.Resources = append(rule.Resources, c.Val())
				if c.NextArg() {
					return rules, c.Errf("Expecting only one resource per line (extra '%s')", c.Val())
				}
			}
		case 3:
			rule.Resources = append(rule.Resources, args[0])
			rule.Username = args[1]
			rule.Password = args[2]
		default:
			return rules, c.ArgErr()
		}

		rules = append(rules, rule)
	}

	return rules, nil
}
