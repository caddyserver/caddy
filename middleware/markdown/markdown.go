// Package markdown is middleware to render markdown files as HTML
// on-the-fly.
package markdown

import (
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/mholt/caddy/middleware"
	"github.com/russross/blackfriday"
	//	"log"
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

// IsIndexFile checks to see if a file is an index file
func (md Markdown) IsIndexFile(file string) bool {
	for _, f := range md.IndexFiles {
		if f == file {
			return true
		}
	}
	return false
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
	Templates map[string]string

	// Map of request URL to static files generated
	StaticFiles map[string]string

	// Links to all markdown pages ordered by date.
	Links []PageLink

	// Directory to store static files
	StaticDir string
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

				fs, err := f.Stat()
				if err != nil {
					return http.StatusNotFound, nil
				}

				// if static site is generated, attempt to use it
				if filepath, ok := m.StaticFiles[fpath]; ok {
					if fs1, err := os.Stat(filepath); err == nil {
						// if markdown has not been modified
						// since static page generation,
						// serve the static page
						if fs.ModTime().UnixNano() < fs1.ModTime().UnixNano() {
							if html, err := ioutil.ReadFile(filepath); err == nil {
								w.Write(html)
								return http.StatusOK, nil
							}
							if os.IsPermission(err) {
								return http.StatusForbidden, err
							}
							return http.StatusNotFound, nil
						}
					}
				}

				if m.StaticDir != "" {
					// Markdown modified or new. Update links.
					//					go func() {
					//						if err := GenerateLinks(md, &md.Configs[i]); err != nil {
					//							log.Println(err)
					//						}
					//					}()
				}

				body, err := ioutil.ReadAll(f)
				if err != nil {
					return http.StatusInternalServerError, err
				}

				ctx := middleware.Context{
					Root: md.FileSys,
					Req:  r,
					URL:  r.URL,
				}
				html, err := md.Process(m, fpath, body, ctx)
				if err != nil {
					return http.StatusInternalServerError, err
				}

				w.Write(html)
				return http.StatusOK, nil
			}
		}
	}

	// Didn't qualify to serve as markdown; pass-thru
	return md.Next.ServeHTTP(w, r)
}
