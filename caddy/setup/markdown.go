package setup

import (
	"net/http"
	"path/filepath"

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
		Root:       c.Root,
		FileSys:    http.Dir(c.Root),
		Configs:    mdconfigs,
		IndexFiles: []string{"index.md"},
	}

	return func(next middleware.Handler) middleware.Handler {
		md.Next = next
		return md
	}, nil
}

func markdownParse(c *Controller) ([]*markdown.Config, error) {
	var mdconfigs []*markdown.Config

	for c.Next() {
		md := &markdown.Config{
			Renderer:   blackfriday.HtmlRenderer(0, "", ""),
			Extensions: make(map[string]struct{}),
			Template:   markdown.GetDefaultTemplate(),
		}

		// Get the path scope
		args := c.RemainingArgs()
		switch len(args) {
		case 0:
			md.PathScope = "/"
		case 1:
			md.PathScope = args[0]
		default:
			return mdconfigs, c.ArgErr()
		}

		// Load any other configuration parameters
		for c.NextBlock() {
			if err := loadParams(c, md); err != nil {
				return mdconfigs, err
			}
		}

		// If no extensions were specified, assume some defaults
		if len(md.Extensions) == 0 {
			md.Extensions[".md"] = struct{}{}
			md.Extensions[".markdown"] = struct{}{}
			md.Extensions[".mdown"] = struct{}{}
		}

		mdconfigs = append(mdconfigs, md)
	}

	return mdconfigs, nil
}

func loadParams(c *Controller, mdc *markdown.Config) error {
	switch c.Val() {
	case "ext":
		for _, ext := range c.RemainingArgs() {
			mdc.Extensions[ext] = struct{}{}
		}
		return nil
	case "css":
		if !c.NextArg() {
			return c.ArgErr()
		}
		mdc.Styles = append(mdc.Styles, c.Val())
		return nil
	case "js":
		if !c.NextArg() {
			return c.ArgErr()
		}
		mdc.Scripts = append(mdc.Scripts, c.Val())
		return nil
	case "template":
		tArgs := c.RemainingArgs()
		switch len(tArgs) {
		default:
			return c.ArgErr()
		case 1:
			fpath := filepath.ToSlash(filepath.Clean(c.Root + string(filepath.Separator) + tArgs[0]))

			if err := markdown.SetTemplate(mdc.Template, "", fpath); err != nil {
				c.Errf("default template parse error: %v", err)
			}
			return nil
		case 2:
			fpath := filepath.ToSlash(filepath.Clean(c.Root + string(filepath.Separator) + tArgs[1]))

			if err := markdown.SetTemplate(mdc.Template, tArgs[0], fpath); err != nil {
				c.Errf("template parse error: %v", err)
			}
			return nil
		}
	case "templatedir":
		if !c.NextArg() {
			return c.ArgErr()
		}
		_, err := mdc.Template.ParseGlob(c.Val())
		if err != nil {
			c.Errf("template load error: %v", err)
		}
		if c.NextArg() {
			return c.ArgErr()
		}
		return nil
	default:
		return c.Err("Expected valid markdown configuration property")
	}
}
