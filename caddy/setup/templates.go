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

		rule.Path = defaultTemplatePath
		rule.Extensions = defaultTemplateExtensions

		args := c.RemainingArgs()

		switch len(args) {
		case 0:
			// Optional block
			for c.NextBlock() {
				switch c.Val() {
				case "path":
					args := c.RemainingArgs()
					if len(args) != 1 {
						return nil, c.ArgErr()
					}
					rule.Path = args[0]

				case "ext":
					args := c.RemainingArgs()
					if len(args) == 0 {
						return nil, c.ArgErr()
					}
					rule.Extensions = args

				case "between":
					args := c.RemainingArgs()
					if len(args) != 2 {
						return nil, c.ArgErr()
					}
					rule.Delims[0] = args[0]
					rule.Delims[1] = args[1]
				}
			}
		default:
			// First argument would be the path
			rule.Path = args[0]

			// Any remaining arguments are extensions
			rule.Extensions = args[1:]
			if len(rule.Extensions) == 0 {
				rule.Extensions = defaultTemplateExtensions
			}
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
