package setup

import (
	"github.com/mholt/caddy/middleware"
	"github.com/mholt/caddy/middleware/templates"
)

// Templates configures a new Templates middleware instance.
func Templates(c *Controller) (middleware.Middleware, error) {
	rules, err := templatesParse(c)
	if err != nil {
		return nil, err
	}

	tmpls := templates.Templates{
		Root:  c.Root,
		Rules: rules,
	}

	return func(next middleware.Handler) middleware.Handler {
		tmpls.Next = next
		return tmpls
	}, nil
}

func templatesParse(c *Controller) ([]templates.Rule, error) {
	var rules []templates.Rule

	for c.Next() {
		var rule templates.Rule

		if c.NextArg() {
			// First argument would be the path
			rule.Path = c.Val()

			// Any remaining arguments are extensions
			rule.Extensions = c.RemainingArgs()
			if len(rule.Extensions) == 0 {
				rule.Extensions = defaultExtensions
			}
		} else {
			rule.Path = defaultPath
			rule.Extensions = defaultExtensions
		}

		rules = append(rules, rule)
	}

	return rules, nil
}

const defaultPath = "/"

var defaultExtensions = []string{".html", ".htm", ".txt"}
