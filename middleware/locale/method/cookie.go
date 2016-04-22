package method

import (
	"net/http"
	"strings"
)

func detectByCookie(r *http.Request, settings *Settings) []string {
	name := strings.TrimSpace(settings.CookieName)
	if name == "" {
		name = "locale"
	}

	locale, _ := r.Cookie(name)

	return []string{locale.Value}
}
