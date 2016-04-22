package method

import "net/http"

// Names holds all known detect methods and their names.
var Names = map[string]Method{
	"header": detectByHeader,
	"cookie": detectByCookie,
}

// Method defines the interface for the locale detect method.
type Method func(*http.Request, *Settings) []string

// Settings defines for a detection method.
type Settings struct {
	CookieName string
}
