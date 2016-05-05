package middleware

import (
	"os"
	"strings"
)

const caseSensitivePathEnv = "CASE_SENSITIVE_PATH"

func init() {
	initCaseSettings()
}

// CaseSensitivePath determines if paths should be case sensitive.
// This is configurable via CASE_SENSITIVE_PATH environment variable.
// It defaults to false.
var CaseSensitivePath = true

// initCaseSettings loads case sensitivity config from environment variable.
//
// This could have been in init, but init cannot be called from tests.
func initCaseSettings() {
	switch os.Getenv(caseSensitivePathEnv) {
	case "0", "false":
		CaseSensitivePath = false
	default:
		CaseSensitivePath = true
	}
}

// Path represents a URI path, maybe with pattern characters.
type Path string

// Matches checks to see if other matches p.
//
// Path matching will probably not always be a direct
// comparison; this method assures that paths can be
// easily and consistently matched.
func (p Path) Matches(other string) bool {
	if CaseSensitivePath {
		return strings.HasPrefix(string(p), other)
	}
	return strings.HasPrefix(strings.ToLower(string(p)), strings.ToLower(other))
}
