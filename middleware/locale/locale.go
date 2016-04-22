package locale

import (
	"net/http"
	"strings"

	"github.com/mholt/caddy/middleware"
	"github.com/mholt/caddy/middleware/locale/method"
)

// Locale is a middleware to detect the user's locale.
type Locale struct {
	Next     middleware.Handler
	Locales  []string
	Methods  []method.Method
	Settings *method.Settings
}

// ServeHTTP implements the middleware.Handler interface.
func (l *Locale) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	candidates := []string{}
	for _, method := range l.Methods {
		candidates = append(candidates, method(r, l.Settings)...)
	}

	locale := l.firstValid(candidates)
	if locale == "" {
		locale = l.defaultLocale()
	}
	r.Header.Set("Detected-Locale", locale)

	return l.Next.ServeHTTP(w, r)
}

func (l *Locale) defaultLocale() string {
	return l.Locales[0]
}

func (l *Locale) firstValid(candidates []string) string {
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if l.isValid(candidate) {
			return candidate
		}
	}
	return ""
}

func (l *Locale) isValid(locale string) bool {
	for _, validLocale := range l.Locales {
		if locale == validLocale {
			return true
		}
	}
	return false
}
