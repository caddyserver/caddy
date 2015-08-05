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
			cfg := &mdconfigs[i]

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

func markdownParse(c *Controller) ([]markdown.Config, error) {
	var mdconfigs []markdown.Config

	for c.Next() {
		md := markdown.Config{
			Renderer:    blackfriday.HtmlRenderer(0, "", ""),
			Templates:   make(map[string]string),
			StaticFiles: make(map[string]string),
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
			case "template":
				tArgs := c.RemainingArgs()
				switch len(tArgs) {
				case 0:
					return mdconfigs, c.ArgErr()
				case 1:
					if _, ok := md.Templates[markdown.DefaultTemplate]; ok {
						return mdconfigs, c.Err("only one default template is allowed, use alias.")
					}
					fpath := filepath.Clean(c.Root + string(filepath.Separator) + tArgs[0])
					md.Templates[markdown.DefaultTemplate] = fpath
				case 2:
					fpath := filepath.Clean(c.Root + string(filepath.Separator) + tArgs[1])
					md.Templates[tArgs[0]] = fpath
				default:
					return mdconfigs, c.ArgErr()
				}
			case "sitegen":
				if c.NextArg() {
					md.StaticDir = path.Join(c.Root, c.Val())
				} else {
					md.StaticDir = path.Join(c.Root, markdown.DefaultStaticDir)
				}
				if c.NextArg() {
					// only 1 argument allowed
					return mdconfigs, c.ArgErr()
				}
			case "dev":
				if c.NextArg() {
					md.Development = strings.ToLower(c.Val()) == "true"
				} else {
					md.Development = true
				}
				if c.NextArg() {
					// only 1 argument allowed
					return mdconfigs, c.ArgErr()
				}
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
