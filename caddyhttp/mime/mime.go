package mime

import (
	"net/http"
	"path"

	"github.com/mholt/caddy/caddyhttp/httpserver"
)

// Config represent a mime config. Map from extension to mime-type.
// Note, this should be safe with concurrent read access, as this is
// not modified concurrently.
type Config map[string]string

// Mime sets Content-Type header of requests based on configurations.
type Mime struct {
	Next    httpserver.Handler
	Configs Config
}

// ServeHTTP implements the httpserver.Handler interface.
func (e Mime) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	// Get a clean /-path, grab the extension
	ext := path.Ext(path.Clean(r.URL.Path))

	if contentType, ok := e.Configs[ext]; ok {
		w.Header().Set("Content-Type", contentType)
	}

	return e.Next.ServeHTTP(w, r)
}
