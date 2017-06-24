package header

import (
	"net/http"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func init() {
	caddy.RegisterPlugin("header", caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	})
}

// setup configures a new Headers middleware instance.
func setup(c *caddy.Controller) error {
	rules, err := headersParse(c)
	if err != nil {
		return err
	}

	httpserver.GetConfig(c).AddMiddleware(func(next httpserver.Handler) httpserver.Handler {
		return Headers{Next: next, Rules: rules}
	})

	return nil
}

func headersParse(c *caddy.Controller) ([]Rule, error) {
	var rules []Rule

	for c.NextLine() {
		var head Rule
		head.Headers = http.Header{}
		var isNewPattern bool

		if !c.NextArg() {
			return rules, c.ArgErr()
		}
		pattern := c.Val()

		// See if we already have a definition for this Path pattern...
		for _, h := range rules {
			if h.Path == pattern {
				head = h
				break
			}
		}

		// ...otherwise, this is a new pattern
		if head.Path == "" {
			head.Path = pattern
			isNewPattern = true
		}

		for c.NextBlock() {
			// A block of headers was opened...
			name := c.Val()
			value := ""

			args := c.RemainingArgs()

			if len(args) > 1 {
				return rules, c.ArgErr()
			} else if len(args) == 1 {
				value = args[0]
			}

			head.Headers.Add(name, value)
		}
		if c.NextArg() {
			// ... or single header was defined as an argument instead.

			name := c.Val()
			value := c.Val()

			if c.NextArg() {
				value = c.Val()
			}

			head.Headers.Add(name, value)
		}

		if isNewPattern {
			rules = append(rules, head)
		} else {
			for i := 0; i < len(rules); i++ {
				if rules[i].Path == pattern {
					rules[i] = head
					break
				}
			}
		}
	}

	return rules, nil
}
