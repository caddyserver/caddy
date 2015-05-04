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

	for c.Next() {
		var rule redirect.Rule
		args := c.RemainingArgs()

		switch len(args) {
		case 1:
			// To specified
			rule.From = "/"
			rule.To = args[0]
			rule.Code = http.StatusMovedPermanently
		case 2:
			// To and Code specified
			rule.From = "/"
			rule.To = args[0]
			if code, ok := httpRedirs[args[1]]; !ok {
				return redirects, c.Err("Invalid redirect code '" + args[1] + "'")
			} else {
				rule.Code = code
			}
		case 3:
			// From, To, and Code specified
			rule.From = args[0]
			rule.To = args[1]
			if code, ok := httpRedirs[args[2]]; !ok {
				return redirects, c.Err("Invalid redirect code '" + args[2] + "'")
			} else {
				rule.Code = code
			}
		default:
			return redirects, c.ArgErr()
		}

		if rule.From == rule.To {
			return redirects, c.Err("Redirect rule cannot allow From and To arguments to be the same.")
		}

		redirects = append(redirects, rule)
	}

	return redirects, nil
}

// httpRedirs is a list of supported HTTP redirect codes.
var httpRedirs = map[string]int{
	"300": 300,
	"301": 301,
	"302": 302,
	"303": 303,
	"304": 304,
	"305": 305,
	"307": 307,
	"308": 308,
}
