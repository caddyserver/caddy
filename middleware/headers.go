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

	for p.Next() {
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

		processHeaderBlock := func() bool {
			if !p.OpenCurlyBrace() {
				return false
			}
			for p.Next() {
				if p.Val() == "}" {
					break
				}
				h := header{Name: p.Val()}
				if p.NextArg() {
					h.Value = p.Val()
				}
				head.Headers = append(head.Headers, h)
			}
			if !p.CloseCurlyBrace() {
				return false
			}
			return true
		}

		// A single header could be declared on the same line, or
		// multiple headers can be grouped by URL pattern, so we have
		// to look for both here.
		if p.NextArg() {
			if p.Val() == "{" {
				if !processHeaderBlock() {
					return nil
				}
			} else {
				h := header{Name: p.Val()}
				if p.NextArg() {
					h.Value = p.Val()
				}
				head.Headers = append(head.Headers, h)
			}
		} else {
			// Okay, it might be an opening curly brace on the next line
			if !p.Next() {
				return p.Err("Parse", "Unexpected EOF")
			}
			if !processHeaderBlock() {
				return nil
			}
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
