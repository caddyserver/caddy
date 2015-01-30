package headers

import "github.com/mholt/caddy/middleware"

func parse(c middleware.Controller) ([]HeaderRule, error) {
	var rules []HeaderRule

	for c.NextLine() {
		var head HeaderRule
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
			h := Header{Name: c.Val()}

			if c.NextArg() {
				h.Value = c.Val()
			}

			head.Headers = append(head.Headers, h)
		}
		if c.NextArg() {
			h := Header{Name: c.Val()}

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
