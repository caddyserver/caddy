package setup

import (
	"strings"

	"github.com/mholt/caddy/middleware"
	"github.com/mholt/caddy/middleware/basicauth"
)

// BasicAuth configures a new BasicAuth middleware instance.
func BasicAuth(c *Controller) (middleware.Middleware, error) {
	root := c.Root

	rules, err := basicAuthParse(c)
	if err != nil {
		return nil, err
	}

	basic := basicauth.BasicAuth{Rules: rules}

	return func(next middleware.Handler) middleware.Handler {
		basic.Next = next
		basic.SiteRoot = root
		return basic
	}, nil
}

func basicAuthParse(c *Controller) ([]basicauth.Rule, error) {
	var rules []basicauth.Rule

	var err error
	for c.Next() {
		var rule basicauth.Rule

		args := c.RemainingArgs()

		switch len(args) {
		case 2:
			rule.Username = args[0]
			if rule.Password, err = passwordMatcher(rule.Username, args[1], c.Root); err != nil {
				return rules, c.Errf("Get password matcher from %s: %v", c.Val(), err)
			}

			for c.NextBlock() {
				rule.Resources = append(rule.Resources, c.Val())
				if c.NextArg() {
					return rules, c.Errf("Expecting only one resource per line (extra '%s')", c.Val())
				}
			}
		case 3:
			rule.Resources = append(rule.Resources, args[0])
			rule.Username = args[1]
			if rule.Password, err = passwordMatcher(rule.Username, args[2], c.Root); err != nil {
				return rules, c.Errf("Get password matcher from %s: %v", c.Val(), err)
			}
		default:
			return rules, c.ArgErr()
		}

		rules = append(rules, rule)
	}

	return rules, nil
}

func passwordMatcher(username, passw, siteRoot string) (basicauth.PasswordMatcher, error) {
	if !strings.HasPrefix(passw, "htpasswd=") {
		return basicauth.PlainMatcher(passw), nil
	}

	return basicauth.GetHtpasswdMatcher(passw[9:], username, siteRoot)
}
