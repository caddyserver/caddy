// Package markdown is middleware to render markdown files as HTML
// on-the-fly.
package markdown

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"os"
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

	// Jail the requests to site root with a mock file system
	FileSys http.FileSystem

	// Next HTTP handler in the chain
	Next middleware.Handler

	// The list of markdown configurations
	Configs []Config

	// The list of index files to try
	IndexFiles []string
}

// Config stores markdown middleware configurations.
type Config struct {
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

	// Map of registered templates
	Templates map[string] string
}

// ServeHTTP implements the http.Handler interface.
func (md Markdown) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	for _, m := range md.Configs {
		if !middleware.Path(r.URL.Path).Matches(m.PathScope) {
			continue
		}

		fpath := r.URL.Path
		if idx, ok := middleware.IndexFile(md.FileSys, fpath, md.IndexFiles); ok {
			fpath = idx
		}

		for _, ext := range m.Extensions {
			if strings.HasSuffix(fpath, ext) {
				f, err := md.FileSys.Open(fpath)
				if err != nil {
					if os.IsPermission(err) {
						return http.StatusForbidden, err
					}
					return http.StatusNotFound, nil
				}

				body, err := ioutil.ReadAll(f)
				if err != nil {
					return http.StatusInternalServerError, err
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

				return http.StatusOK, nil
			}
		}
	}

	// Didn't qualify to serve as markdown; pass-thru
	return md.Next.ServeHTTP(w, r)
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
