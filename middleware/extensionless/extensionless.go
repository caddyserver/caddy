// Extensionless is middleware for clean URLs. A root path is
// passed in as well as possible extensions to add, internally,
// to paths requested. The first path+ext that matches a resource
// that exists will be used.
package extensionless

import (
	"net/http"
	"os"
	"strings"

	"github.com/mholt/caddy/middleware"
)

// New creates a new instance of middleware that assumes extensions
// so the site can use cleaner, extensionless URLs
func New(c middleware.Controller) (middleware.Middleware, error) {
	var extensions []string
	var root = c.Root() // TODO: Big gotcha! Save this now before it goes away! We can't get this later during a request!

	for c.Next() {
		if !c.NextArg() {
			return nil, c.ArgErr()
		}
		extensions = append(extensions, c.Val())
		for c.NextArg() {
			extensions = append(extensions, c.Val())
		}
	}

	resourceExists := func(path string) bool {
		_, err := os.Stat(root + path)
		// technically we should use os.IsNotExist(err)
		// but we don't handle any other kinds of errors anyway
		return err == nil
	}

	hasExt := func(r *http.Request) bool {
		if r.URL.Path[len(r.URL.Path)-1] == '/' {
			// directory
			return true
		}
		lastSep := strings.LastIndex(r.URL.Path, "/")
		lastDot := strings.LastIndex(r.URL.Path, ".")
		return lastDot > lastSep
	}

	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if !hasExt(r) {
				for _, ext := range extensions {
					if resourceExists(r.URL.Path + ext) {
						r.URL.Path = r.URL.Path + ext
						break
					}
				}
			}
			next(w, r)
		}
	}, nil
}
