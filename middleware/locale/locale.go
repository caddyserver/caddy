package locale

import (
	"fmt"
	"net/http"
	"os"
	"path"
	"strings"

	"github.com/mholt/caddy/middleware"
)

// Locale is a middleware to detect the user's locale.
type Locale struct {
	Next          middleware.Handler
	RootPath      string
	DetectMethods []DetectMethod
	DefaultLocale string
}

// ServeHTTP implements the middleware.Handler interface.
func (l *Locale) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	candidates := []string{}
	for _, detectMethod := range l.DetectMethods {
		switch detectMethod {
		case DetectMethodHeader:
			candidates = append(candidates, fromHeader(r)...)
		}
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

func fromHeader(r *http.Request) []string {
	parts := strings.Split(r.Header.Get("Accept-Language"), ",")

	locales := []string{}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		locale := strings.Split(part, ";")[0]
		locales = append(locales, locale)
	}

	return locales
}

// resourceExists returns true if the file specified at path exists; false otherwise.
func resourceExists(path string) bool {
	_, err := os.Stat(path)
	// technically we should use os.IsNotExist(err) but we don't handle any other kinds
	// of errors anyway.
	return err == nil
}
