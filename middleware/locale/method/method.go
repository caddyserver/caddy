package method

import "net/http"

// Names holds all known detect methods and their names.
var Names = map[string]Method{
	"header": &Header{},
}

// Method defines the interface for the locale detect method.
type Method interface {
	Name() string
	Detect(*http.Request) []string
}
