package mime

import (
	"net/http"
	"path/filepath"

	"github.com/mholt/caddy/middleware"
)

// Config represent a mime config.
type Config struct {
	Ext         string
	ContentType string
}

// SetContent sets the Content-Type header of the request if the request path
// is supported.
func (c Config) SetContent(w http.ResponseWriter, r *http.Request) bool {
	ext := filepath.Ext(r.URL.Path)
	if ext != c.Ext {
		return false
	}
	w.Header().Set("Content-Type", c.ContentType)
	return true
}

// Mime sets Content-Type header of requests based on configurations.
type Mime struct {
	Next    middleware.Handler
	Configs []Config
}

// ServeHTTP implements the middleware.Handler interface.
func (e Mime) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	for _, c := range e.Configs {
		if ok := c.SetContent(w, r); ok {
			break
		}
	}
	return e.Next.ServeHTTP(w, r)
}
