package middleware

import (
	"net/http"
	"os"
	"strings"
)

// Extensionless is middleware for clean URLs. A root path is
// passed in as well as possible extensions to add, internally,
// to paths requested. The first path+ext that matches a resource
// that exists will be used.
func Extensionless(p parser) Middleware {
	var extensions []string
	var root = p.Root() // TODO: Big gotcha! Save this now before it goes away! We can't get this later during a request!

	for p.Next() {
		if !p.NextArg() {
			return p.ArgErr()
		}
		extensions = append(extensions, p.Val())
		for p.NextArg() {
			extensions = append(extensions, p.Val())
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
	}
}
