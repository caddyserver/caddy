package setup

import (
	"net/http"
	"path"
	"path/filepath"
	"strings"

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

	// Sweep the whole path at startup to at least generate link index, maybe generate static site
	c.Startup = append(c.Startup, func() error {
		for i := range mdconfigs {
			cfg := mdconfigs[i]

			// Generate link index and static files (if enabled)
			if err := markdown.GenerateStatic(md, cfg); err != nil {
				return err
			}

			// Watch file changes for static site generation if not in development mode.
			if !cfg.Development {
				markdown.Watch(md, cfg, markdown.DefaultInterval)
			}
		}

		return nil
	})

	return func(next middleware.Handler) middleware.Handler {
		md.Next = next
		return md
	}, nil
}

func markdownParse(c *Controller) ([]*markdown.Config, error) {
	var mdconfigs []*markdown.Config

	for c.Next() {
		md := &markdown.Config{
			Renderer:    blackfriday.HtmlRenderer(0, "", ""),
			Templates:   make(map[string]string),
			StaticFiles: make(map[string]string),
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
			md.Extensions = []string{".md", ".markdown", ".mdown"}
		}

		mdconfigs = append(mdconfigs, md)
	}

	return mdconfigs, nil
}

func loadParams(c *Controller, mdc *markdown.Config) error {
	switch c.Val() {
	case "ext":
		exts := c.RemainingArgs()
		if len(exts) == 0 {
			return c.ArgErr()
		}
		mdc.Extensions = append(mdc.Extensions, exts...)
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
		case 0:
			return c.ArgErr()
		case 1:
			if _, ok := mdc.Templates[markdown.DefaultTemplate]; ok {
				return c.Err("only one default template is allowed, use alias.")
			}
			fpath := filepath.ToSlash(filepath.Clean(c.Root + string(filepath.Separator) + tArgs[0]))
			mdc.Templates[markdown.DefaultTemplate] = fpath
			return nil
		case 2:
			fpath := filepath.ToSlash(filepath.Clean(c.Root + string(filepath.Separator) + tArgs[1]))
			mdc.Templates[tArgs[0]] = fpath
			return nil
		default:
			return c.ArgErr()
		}
	case "sitegen":
		if c.NextArg() {
			mdc.StaticDir = path.Join(c.Root, c.Val())
		} else {
			mdc.StaticDir = path.Join(c.Root, markdown.DefaultStaticDir)
		}
		if c.NextArg() {
			// only 1 argument allowed
			return c.ArgErr()
		}
		return nil
	case "dev":
		if c.NextArg() {
			mdc.Development = strings.ToLower(c.Val()) == "true"
		} else {
			mdc.Development = true
		}
		if c.NextArg() {
			// only 1 argument allowed
			return c.ArgErr()
		}
		return nil
	default:
		return c.Err("Expected valid markdown configuration property")
	}
}
