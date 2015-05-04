package setup

import (
	"github.com/mholt/caddy/middleware"
	"github.com/mholt/caddy/middleware/markdown"
	"github.com/russross/blackfriday"
)

// Markdown configures a new Markdown middleware instance.
func Markdown(c *Controller) (middleware.Middleware, error) {
	mdconfigs, err := markdownParse(c)
	if err != nil {
		return nil, err
	}

	md := markdown.Markdown{
		Root:    c.Root,
		Configs: mdconfigs,
	}

	return func(next middleware.Handler) middleware.Handler {
		md.Next = next
		return md
	}, nil
}

func markdownParse(c *Controller) ([]markdown.Config, error) {
	var mdconfigs []markdown.Config

	for c.Next() {
		md := markdown.Config{
			Renderer: blackfriday.HtmlRenderer(0, "", ""),
		}

		// Get the path scope
		if !c.NextArg() || c.Val() == "{" {
			return mdconfigs, c.ArgErr()
		}
		md.PathScope = c.Val()

		// Load any other configuration parameters
		for c.NextBlock() {
			switch c.Val() {
			case "ext":
				exts := c.RemainingArgs()
				if len(exts) == 0 {
					return mdconfigs, c.ArgErr()
				}
				md.Extensions = append(md.Extensions, exts...)
			case "css":
				if !c.NextArg() {
					return mdconfigs, c.ArgErr()
				}
				md.Styles = append(md.Styles, c.Val())
			case "js":
				if !c.NextArg() {
					return mdconfigs, c.ArgErr()
				}
				md.Scripts = append(md.Scripts, c.Val())
			default:
				return mdconfigs, c.Err("Expected valid markdown configuration property")
			}
		}

		// If no extensions were specified, assume .md
		if len(md.Extensions) == 0 {
			md.Extensions = []string{".md"}
		}

		mdconfigs = append(mdconfigs, md)
	}

	return mdconfigs, nil
}
