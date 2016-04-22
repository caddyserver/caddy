package locale

import (
	"fmt"
	"net/http"
	"os"
	"path"

	"github.com/mholt/caddy/middleware"
	"github.com/mholt/caddy/middleware/locale/method"
)

// Locale is a middleware to detect the user's locale.
type Locale struct {
	Next          middleware.Handler
	RootPath      string
	Methods       []method.Method
	DefaultLocale string
}

// ServeHTTP implements the middleware.Handler interface.
func (l *Locale) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	candidates := []string{}
	for _, method := range l.Methods {
		candidates = append(candidates, method.Detect(r)...)
	}
	candidates = append(candidates, l.DefaultLocale)

	if ext := path.Ext(r.URL.Path); ext != "" {
		for _, candidate := range candidates {
			candidatePath := fmt.Sprintf("%s.%s%s", r.URL.Path[:len(r.URL.Path)-len(ext)], candidate, ext)

			if resourceExists(path.Join(l.RootPath, candidatePath)) {
				r.URL.Path = candidatePath
				w.Header().Set("Content-Language", candidate)
			}
		}
	}

	return l.Next.ServeHTTP(w, r)
}

// resourceExists returns true if the file specified at path exists; false otherwise.
func resourceExists(path string) bool {
	_, err := os.Stat(path)
	// technically we should use os.IsNotExist(err) but we don't handle any other kinds
	// of errors anyway.
	return err == nil
}
