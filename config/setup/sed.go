package setup

import (
	"github.com/mholt/caddy/middleware"
	"github.com/mholt/caddy/middleware/sed"
)

func Sed(c *Controller) (middleware.Middleware, error) {
	rules, err := sedParse(c)
	if err != nil {
		return nil, err
	}

	return func(next middleware.Handler) middleware.Handler {
		return sed.Sed{Next: next, Rules: rules}
	}, nil
}

func sedParse(c *Controller) ([]sed.Rule, error) {
	var rules []sed.Rule

	for c.NextLine() {
		var head sed.Rule
		var isNewPattern bool

		if !c.NextArg() {
			return rules, c.ArgErr()
		}
		pattern := c.Val()

		// See if we already have a definition for this URL pattern...
		for _, r := range rules {
			if r.Url == pattern {
				head = r
				break
			}
		}

		// ...otherwise, this is a new pattern
		if head.Url == "" {
			head.Url = pattern
			isNewPattern = true
		}

		for c.NextBlock() {
			// A block of sed was opened...
			p := sed.Pattern{Find: c.Val()}

			if !c.NextArg() {
				return rules, c.ArgErr()
			}
			p.Replace = c.Val()

			head.Patterns = append(head.Patterns, p)
		}
		if c.NextArg() {
			// ... or single sed was defined as an argument instead.
			p := sed.Pattern{Find: c.Val()}

			if !c.NextArg() {
				return rules, c.ArgErr()
			}
			p.Replace = c.Val()

			head.Patterns = append(head.Patterns, p)
		}

		if isNewPattern {
			rules = append(rules, head)
		} else {
			for i := 0; i < len(rules); i++ {
				if rules[i].Url == pattern {
					rules[i] = head
					break
				}
			}
		}
	}

	return rules, nil
}
