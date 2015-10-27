package setup

import (
	"net/http"

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
		Rules:   rules,
		Root:    c.Root,
		FileSys: http.Dir(c.Root),
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
				rule.Extensions = defaultTemplateExtensions
			}
		} else {
			rule.Path = defaultTemplatePath
			rule.Extensions = defaultTemplateExtensions
		}

		for _, ext := range rule.Extensions {
			rule.IndexFiles = append(rule.IndexFiles, "index"+ext)
		}

		rules = append(rules, rule)
	}

	return rules, nil
}

const defaultTemplatePath = "/"

var defaultTemplateExtensions = []string{".html", ".htm", ".tmpl", ".tpl", ".txt"}
