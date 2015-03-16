// Package markdown is middleware to render markdown files as HTML
// on-the-fly.
package markdown

import (
	"io/ioutil"
	"net/http"
	"path"
	"strings"

	"github.com/mholt/caddy/middleware"
	"github.com/russross/blackfriday"
)

// New creates a new instance of Markdown middleware that
// renders markdown to HTML on-the-fly.
func New(c middleware.Controller) (middleware.Middleware, error) {
	md, err := parse(c)
	if err != nil {
		return nil, err
	}

	md.Root = c.Root()
	md.Renderer = blackfriday.HtmlRenderer(0, "", "")

	return func(next http.HandlerFunc) http.HandlerFunc {
		md.Next = next
		return md.ServeHTTP
	}, nil
}

// Markdown stores the configuration necessary to serve the Markdown middleware.
type Markdown struct {
	// Server root
	Root string

	// Next HTTP handler in the chain
	Next http.HandlerFunc

	// Markdown renderer
	Renderer blackfriday.Renderer

	// Base path to match
	PathScope string

	// List of extensions to consider as markdown files
	Extensions []string

	// List of style sheets to load for each markdown file
	Styles []string

	// List of JavaScript files to load for each markdown file
	Scripts []string
}

// ServeHTTP implements the http.Handler interface.
func (m Markdown) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if middleware.Path(r.URL.Path).Matches(m.PathScope) {
		for _, ext := range m.Extensions {
			if strings.HasSuffix(r.URL.Path, ext) {
				fpath := m.Root + r.URL.Path

				body, err := ioutil.ReadFile(fpath)
				if err != nil {
					panic(err) // TODO
				}

				content := blackfriday.Markdown(body, m.Renderer, 0)

				var scripts, styles string
				for _, style := range m.Styles {
					styles += strings.Replace(cssTemplate, "{{url}}", style, 1) + "\r\n"
				}
				for _, script := range m.Scripts {
					scripts += strings.Replace(jsTemplate, "{{url}}", script, 1) + "\r\n"
				}

				html := htmlTemplate
				html = strings.Replace(html, "{{title}}", path.Base(fpath), 1)
				html = strings.Replace(html, "{{css}}", styles, 1)
				html = strings.Replace(html, "{{js}}", scripts, 1)
				html = strings.Replace(html, "{{body}}", string(content), 1)

				w.Write([]byte(html))
				return
			}
		}
	}

	m.Next(w, r)
}

// parse fills up a new instance of Markdown middleware.
func parse(c middleware.Controller) (Markdown, error) {
	var md Markdown

	for c.Next() {
		// Get the path scope
		if !c.NextArg() {
			return md, c.ArgErr()
		}
		md.PathScope = c.Val()

		// Load any other configuration parameters
		for c.NextBlock() {
			switch c.Val() {
			case "ext":
				exts := c.RemainingArgs()
				if len(exts) == 0 {
					return md, c.ArgErr()
				}
				md.Extensions = append(md.Extensions, exts...)
			case "css":
				if !c.NextArg() {
					return md, c.ArgErr()
				}
				md.Styles = append(md.Styles, c.Val())
			case "js":
				if !c.NextArg() {
					return md, c.ArgErr()
				}
				md.Scripts = append(md.Scripts, c.Val())
			default:
				return md, c.Err("Expected valid markdown configuration property")
			}
		}

	}

	return md, nil
}

const (
	htmlTemplate = `<!DOCTYPE html>
<html>
	<head>
		<title>{{title}}</title>
		<meta charset="utf-8">
		{{css}}
		{{js}}
	</head>
	<body>
		{{body}}
	</body>
</html>`
	cssTemplate = `<link rel="stylesheet" href="{{url}}">`
	jsTemplate  = `<script src="{{url}}"></script>`
)
