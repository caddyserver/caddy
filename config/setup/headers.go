package setup

import (
	"github.com/mholt/caddy/middleware"
	"github.com/mholt/caddy/middleware/headers"
)

// Headers configures a new Headers middleware instance.
func Headers(c *Controller) (middleware.Middleware, error) {
	rules, err := headersParse(c)
	if err != nil {
		return nil, err
	}

	return func(next middleware.Handler) middleware.Handler {
		return headers.Headers{Next: next, Rules: rules}
	}, nil
}

func headersParse(c *Controller) ([]headers.Rule, error) {
	var rules []headers.Rule

	for c.NextLine() {
		var head headers.Rule
		var isNewPattern bool

		if !c.NextArg() {
			return rules, c.ArgErr()
		}
		pattern := c.Val()

		// See if we already have a definition for this URL pattern...
		for _, h := range rules {
			if h.Url == pattern {
				head = h
				break
			}
		}

		// ...otherwise, this is a new pattern
		if head.Url == "" {
			head.Url = pattern
			isNewPattern = true
		}

		for c.NextBlock() {
			// A block of headers was opened...

			h := headers.Header{Name: c.Val()}

			if c.NextArg() {
				h.Value = c.Val()
			}

			head.Headers = append(head.Headers, h)
		}
		if c.NextArg() {
			// ... or single header was defined as an argument instead.

			h := headers.Header{Name: c.Val()}

			h.Value = c.Val()

			if c.NextArg() {
				h.Value = c.Val()
			}

			head.Headers = append(head.Headers, h)
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
