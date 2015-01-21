package middleware

import "net/http"

// Headers is middleware that adds headers to the responses
// for requests matching a certain path.
func Headers(p parser) Middleware {
	type (
		// Header represents a single HTTP header, simply a name and value.
		header struct {
			Name  string
			Value string
		}

		// Headers groups a slice of HTTP headers by a URL pattern.
		headers struct {
			Url     string
			Headers []header
		}
	)
	var rules []headers

	for p.NextLine() {
		var head headers
		var isNewPattern bool

		if !p.NextArg() {
			return p.ArgErr()
		}
		pattern := p.Val()

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

		for p.NextBlock() {
			h := header{Name: p.Val()}

			if p.NextArg() {
				h.Value = p.Val()
			}

			head.Headers = append(head.Headers, h)
		}
		if p.NextArg() {
			h := header{Name: p.Val()}

			h.Value = p.Val()

			if p.NextArg() {
				h.Value = p.Val()
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

	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			for _, rule := range rules {
				if Path(r.URL.Path).Matches(rule.Url) {
					for _, header := range rule.Headers {
						w.Header().Set(header.Name, header.Value)
					}
				}
			}
			next(w, r)
		}
	}
}
