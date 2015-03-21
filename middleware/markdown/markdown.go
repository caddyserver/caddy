// Package markdown is middleware to render markdown files as HTML
// on-the-fly.
package markdown

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"path"
	"strings"

	"github.com/mholt/caddy/middleware"
	"github.com/russross/blackfriday"
)

// Markdown implements a layer of middleware that serves
// markdown as HTML.
type Markdown struct {
	// Server root
	Root string

	// Next HTTP handler in the chain
	Next http.HandlerFunc

	// The list of markdown configurations
	Configs []MarkdownConfig
}

// MarkdownConfig stores markdown middleware configurations.
type MarkdownConfig struct {
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

// New creates a new instance of Markdown middleware that
// renders markdown to HTML on-the-fly.
func New(c middleware.Controller) (middleware.Middleware, error) {
	mdconfigs, err := parse(c)
	if err != nil {
		return nil, err
	}

	md := Markdown{
		Root:    c.Root(),
		Configs: mdconfigs,
	}

	return func(next http.HandlerFunc) http.HandlerFunc {
		md.Next = next
		return md.ServeHTTP
	}, nil
}

// ServeHTTP implements the http.Handler interface.
func (md Markdown) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	for _, m := range md.Configs {
		if !middleware.Path(r.URL.Path).Matches(m.PathScope) {
			continue
		}

		for _, ext := range m.Extensions {
			if strings.HasSuffix(r.URL.Path, ext) {
				fpath := md.Root + r.URL.Path

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

				// Title is first line (length-limited), otherwise filename
				title := path.Base(fpath)
				newline := bytes.Index(body, []byte("\n"))
				if newline > -1 {
					firstline := body[:newline]
					newTitle := strings.TrimSpace(string(firstline))
					if len(newTitle) > 1 {
						if len(newTitle) > 128 {
							title = newTitle[:128]
						} else {
							title = newTitle
						}
					}
				}

				html := htmlTemplate
				html = strings.Replace(html, "{{title}}", title, 1)
				html = strings.Replace(html, "{{css}}", styles, 1)
				html = strings.Replace(html, "{{js}}", scripts, 1)
				html = strings.Replace(html, "{{body}}", string(content), 1)

				w.Write([]byte(html))

				return
			}
		}
	}

	// Didn't qualify to serve as markdown; pass-thru
	md.Next(w, r)
}

// parse creates new instances of Markdown middleware.
func parse(c middleware.Controller) ([]MarkdownConfig, error) {
	var mdconfigs []MarkdownConfig

	for c.Next() {
		md := MarkdownConfig{
			Renderer: blackfriday.HtmlRenderer(0, "", ""),
		}

		// Get the path scope
		if !c.NextArg() {
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

		mdconfigs = append(mdconfigs, md)
	}

	return mdconfigs, nil
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
