package markdown

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/mholt/caddy/middleware"
)

// GenerateStatic generate static files and link index from markdowns.
// It only generates static files if it is enabled (cfg.StaticDir
// must be set).
func GenerateStatic(md Markdown, cfg *Config) error {
	generated, err := generateLinks(md, cfg)
	if err != nil {
		return err
	}

	// No new file changes, return.
	if !generated {
		return nil
	}

	// If static site generation is enabled.
	if cfg.StaticDir != "" {
		if err := generateStaticHTML(md, cfg); err != nil {
			return err
		}
	}
	return nil
}

type linkGenerator struct {
	gens map[*Config]*linkGen
	sync.Mutex
}

var generator = linkGenerator{gens: make(map[*Config]*linkGen)}

// generateLinks generates links to all markdown files ordered by newest date.
// This blocks until link generation is done. When called by multiple goroutines,
// the first caller starts the generation and others only wait.
// It returns if generation is done and any error that occurred.
func generateLinks(md Markdown, cfg *Config) (bool, error) {
	generator.Lock()

	// if link generator exists for config and running, wait.
	if g, ok := generator.gens[cfg]; ok {
		if g.started() {
			g.addWaiter()
			generator.Unlock()
			g.Wait()
			// another goroutine has done the generation.
			return false, g.lastErr
		}
	}

	g := &linkGen{}
	generator.gens[cfg] = g
	generator.Unlock()

	generated := g.generateLinks(md, cfg)
	g.discardWaiters()
	return generated, g.lastErr
}

// generateStaticFiles generates static html files from markdowns.
func generateStaticHTML(md Markdown, cfg *Config) error {
	// If generated site already exists, clear it out
	_, err := os.Stat(cfg.StaticDir)
	if err == nil {
		err := os.RemoveAll(cfg.StaticDir)
		if err != nil {
			return err
		}
	}

	fp := filepath.Join(md.Root, cfg.PathScope)

	return filepath.Walk(fp, func(path string, info os.FileInfo, err error) error {
		for _, ext := range cfg.Extensions {
			if !info.IsDir() && strings.HasSuffix(info.Name(), ext) {
				// Load the file
				body, err := ioutil.ReadFile(path)
				if err != nil {
					return err
				}

				// Get the relative path as if it were a HTTP request,
				// then prepend with "/" (like a real HTTP request)
				reqPath, err := filepath.Rel(md.Root, path)
				if err != nil {
					return err
				}
				reqPath = "/" + reqPath

				// Generate the static file
				ctx := middleware.Context{Root: md.FileSys}
				_, err = md.Process(*cfg, reqPath, body, ctx)
				if err != nil {
					return err
				}

				break // don't try other file extensions
			}
		}
		return nil
	})
}

// computeDirHash computes an hash on static directory of c.
func computeDirHash(md Markdown, c Config) (string, error) {
	dir := filepath.Join(md.Root, c.PathScope)
	if _, err := os.Stat(dir); err != nil {
		return "", err
	}

	hashString := ""
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if !info.IsDir() && c.IsValidExt(filepath.Ext(path)) {
			hashString += fmt.Sprintf("%v%v%v%v", info.ModTime(), info.Name(), info.Size(), path)
		}
		return nil
	})
	if err != nil {
		return "", err
	}

	sum := md5.Sum([]byte(hashString))
	return hex.EncodeToString(sum[:]), nil
}
