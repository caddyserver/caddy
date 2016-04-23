package method

import "net/http"

// Names holds all known detect methods and their names.
var Names = map[string]Method{
	"header": detectByHeader,
	"cookie": detectByCookie,
}

// Method defines the alias for the locale detect method.
type Method func(*http.Request, *Configuration) []string

// Configuration defines the configuration for detection methods.
type Configuration struct {
	CookieName string
}
