package basicauth

import (
	"strings"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func init() {
	caddy.RegisterPlugin("basicauth", caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	})
}

// setup configures a new BasicAuth middleware instance.
func setup(c *caddy.Controller) error {
	cfg := httpserver.GetConfig(c)
	root := cfg.Root

	rules, err := basicAuthParse(c)
	if err != nil {
		return err
	}

	basic := BasicAuth{Rules: rules}

	cfg.AddMiddleware(func(next httpserver.Handler) httpserver.Handler {
		basic.Next = next
		basic.SiteRoot = root
		return basic
	})

	return nil
}

func basicAuthParse(c *caddy.Controller) ([]Rule, error) {
	var rules []Rule
	cfg := httpserver.GetConfig(c)

	var err error
	for c.Next() {
		var rule Rule

		args := c.RemainingArgs()

		switch len(args) {
		case 2:
			rule.Username = args[0]
			if rule.Password, err = passwordMatcher(rule.Username, args[1], cfg.Root); err != nil {
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
			if rule.Password, err = passwordMatcher(rule.Username, args[2], cfg.Root); err != nil {
				return rules, c.Errf("Get password matcher from %s: %v", c.Val(), err)
			}
		default:
			return rules, c.ArgErr()
		}

		rules = append(rules, rule)
	}

	return rules, nil
}

func passwordMatcher(username, passw, siteRoot string) (PasswordMatcher, error) {
	if !strings.HasPrefix(passw, "htpasswd=") {
		return PlainMatcher(passw), nil
	}
	return GetHtpasswdMatcher(passw[9:], username, siteRoot)
}
