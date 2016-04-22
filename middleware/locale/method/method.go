package method

import "net/http"

// Names holds all known detect methods and their names.
var Names = map[string]Method{
	"header": detectByHeader,
}

// Method defines the interface for the locale detect method.
type Method func(*http.Request) []string
