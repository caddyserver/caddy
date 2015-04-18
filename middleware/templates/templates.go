package templates

import (
	"html/template"
	"net/http"
	"path"

	"github.com/mholt/caddy/middleware"
)

// New constructs a new Templates middleware instance.
func New(c middleware.Controller) (middleware.Middleware, error) {
	rules, err := parse(c)
	if err != nil {
		return nil, err
	}

	tmpls := Templates{
		Root:  c.Root(),
		Rules: rules,
	}

	return func(next middleware.Handler) middleware.Handler {
		tmpls.Next = next
		return tmpls
	}, nil
}

// ServeHTTP implements the middleware.Handler interface.
func (t Templates) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	for _, rule := range t.Rules {
		if !middleware.Path(r.URL.Path).Matches(rule.Path) {
			continue
		}

		reqExt := path.Ext(r.URL.Path)

		for _, ext := range rule.Extensions {
			if reqExt == ext {
				// Create execution context
				ctx := context{root: http.Dir(t.Root), req: r}

				// Build the template
				tpl, err := template.ParseFiles(t.Root + r.URL.Path)
				if err != nil {
					return http.StatusInternalServerError, err
				}

				// Execute it
				err = tpl.Execute(w, ctx)
				if err != nil {
					return http.StatusInternalServerError, err
				}

				return http.StatusOK, nil
			}
		}
	}

	return t.Next.ServeHTTP(w, r)
}

func parse(c middleware.Controller) ([]Rule, error) {
	var rules []Rule

	for c.Next() {
		var rule Rule

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

// Templates is middleware to render templated files as the HTTP response.
type Templates struct {
	Next  middleware.Handler
	Root  string
	Rules []Rule
}

// Rule represents a template rule. A template will only execute
// with this rule if the request path matches the Path specified
// and requests a resource with one of the extensions specified.
type Rule struct {
	Path       string
	Extensions []string
}

const defaultPath = "/"

var defaultExtensions = []string{".html", ".htm", ".txt"}
