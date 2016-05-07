package method

import "net/http"

func detectByCookie(r *http.Request, c *Configuration) []string {
	locale, _ := r.Cookie(c.CookieName)
	if locale == nil {
		return []string{}
	}
	return []string{locale.Value}
}
