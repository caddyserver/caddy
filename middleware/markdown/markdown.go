// Package markdown is middleware to render markdown files as HTML
// on-the-fly.
package markdown

import (
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"

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

	// Stores a directory hash to check for changes.
	linksHash string

	// Directory to store static files
	StaticDir string

	// If in development mode. i.e. Actively editing markdown files.
	Development bool

	sync.RWMutex
}

// IsValidExt checks to see if an extension is a valid markdown extension
// for config.
func (c Config) IsValidExt(ext string) bool {
	for _, e := range c.Extensions {
		if e == ext {
			return true
		}
	}
	return false
}

// ServeHTTP implements the http.Handler interface.
func (md Markdown) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	for _, cfg := range md.Configs {
		if !middleware.Path(r.URL.Path).Matches(cfg.PathScope) {
			continue
		}

		fpath := r.URL.Path
		if idx, ok := middleware.IndexFile(md.FileSys, fpath, md.IndexFiles); ok {
			fpath = idx
		}

		for _, ext := range cfg.Extensions {
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

				// if development is set, scan directory for file changes for links.
				if cfg.Development {
					if err := GenerateStatic(md, &cfg); err != nil {
						log.Println("On-demand generation error (markdown):", err)
					}
				}

				// if static site is generated, attempt to use it
				if filepath, ok := cfg.StaticFiles[fpath]; ok {
					if fs1, err := os.Stat(filepath); err == nil {
						// if markdown has not been modified since static page
						// generation, serve the static page
						if fs.ModTime().Before(fs1.ModTime()) {
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

				body, err := ioutil.ReadAll(f)
				if err != nil {
					return http.StatusInternalServerError, err
				}

				ctx := middleware.Context{
					Root: md.FileSys,
					Req:  r,
					URL:  r.URL,
				}
				html, err := md.Process(cfg, fpath, body, ctx)
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
