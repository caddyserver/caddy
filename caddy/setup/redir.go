package setup

import (
	"net/http"

	"github.com/mholt/caddy/middleware"
	"github.com/mholt/caddy/middleware/redirect"
)

// Redir configures a new Redirect middleware instance.
func Redir(c *Controller) (middleware.Middleware, error) {
	rules, err := redirParse(c)
	if err != nil {
		return nil, err
	}

	return func(next middleware.Handler) middleware.Handler {
		return redirect.Redirect{Next: next, Rules: rules}
	}, nil
}

func redirParse(c *Controller) ([]redirect.Rule, error) {
	var redirects []redirect.Rule

	// setRedirCode sets the redirect code for rule if it can, or returns an error
	setRedirCode := func(code string, rule *redirect.Rule) error {
		if code == "meta" {
			rule.Meta = true
		} else if codeNumber, ok := httpRedirs[code]; ok {
			rule.Code = codeNumber
		} else {
			return c.Errf("Invalid redirect code '%v'", code)
		}
		return nil
	}

	// checkAndSaveRule checks the rule for validity (except the redir code)
	// and saves it if it's valid, or returns an error.
	checkAndSaveRule := func(rule redirect.Rule) error {
		if rule.FromPath == rule.To {
			return c.Err("'from' and 'to' values of redirect rule cannot be the same")
		}

		for _, otherRule := range redirects {
			if otherRule.FromPath == rule.FromPath {
				return c.Errf("rule with duplicate 'from' value: %s -> %s", otherRule.FromPath, otherRule.To)
			}
		}

		redirects = append(redirects, rule)
		return nil
	}

	for c.Next() {
		args := c.RemainingArgs()

		var hadOptionalBlock bool
		for c.NextBlock() {
			hadOptionalBlock = true

			var rule redirect.Rule

			if c.Config.TLS.Enabled {
				rule.FromScheme = "https"
			} else {
				rule.FromScheme = "http"
			}

			// Set initial redirect code
			// BUG: If the code is specified for a whole block and that code is invalid,
			// the line number will appear on the first line inside the block, even if that
			// line overwrites the block-level code with a valid redirect code. The program
			// still functions correctly, but the line number in the error reporting is
			// misleading to the user.
			if len(args) == 1 {
				err := setRedirCode(args[0], &rule)
				if err != nil {
					return redirects, err
				}
			} else {
				rule.Code = http.StatusMovedPermanently // default code
			}

			// RemainingArgs only gets the values after the current token, but in our
			// case we want to include the current token to get an accurate count.
			insideArgs := append([]string{c.Val()}, c.RemainingArgs()...)

			switch len(insideArgs) {
			case 1:
				// To specified (catch-all redirect)
				// Not sure why user is doing this in a table, as it causes all other redirects to be ignored.
				// As such, this feature remains undocumented.
				rule.FromPath = "/"
				rule.To = insideArgs[0]
			case 2:
				// From and To specified
				rule.FromPath = insideArgs[0]
				rule.To = insideArgs[1]
			case 3:
				// From, To, and Code specified
				rule.FromPath = insideArgs[0]
				rule.To = insideArgs[1]
				err := setRedirCode(insideArgs[2], &rule)
				if err != nil {
					return redirects, err
				}
			default:
				return redirects, c.ArgErr()
			}

			err := checkAndSaveRule(rule)
			if err != nil {
				return redirects, err
			}
		}

		if !hadOptionalBlock {
			var rule redirect.Rule

			if c.Config.TLS.Enabled {
				rule.FromScheme = "https"
			} else {
				rule.FromScheme = "http"
			}

			rule.Code = http.StatusMovedPermanently // default

			switch len(args) {
			case 1:
				// To specified (catch-all redirect)
				rule.FromPath = "/"
				rule.To = args[0]
			case 2:
				// To and Code specified (catch-all redirect)
				rule.FromPath = "/"
				rule.To = args[0]
				err := setRedirCode(args[1], &rule)
				if err != nil {
					return redirects, err
				}
			case 3:
				// From, To, and Code specified
				rule.FromPath = args[0]
				rule.To = args[1]
				err := setRedirCode(args[2], &rule)
				if err != nil {
					return redirects, err
				}
			default:
				return redirects, c.ArgErr()
			}

			err := checkAndSaveRule(rule)
			if err != nil {
				return redirects, err
			}
		}
	}

	return redirects, nil
}

// httpRedirs is a list of supported HTTP redirect codes.
var httpRedirs = map[string]int{
	"300": http.StatusMultipleChoices,
	"301": http.StatusMovedPermanently,
	"302": http.StatusFound, // (NOT CORRECT for "Temporary Redirect", see 307)
	"303": http.StatusSeeOther,
	"304": http.StatusNotModified,
	"305": http.StatusUseProxy,
	"307": http.StatusTemporaryRedirect,
	"308": 308, // Permanent Redirect
}
