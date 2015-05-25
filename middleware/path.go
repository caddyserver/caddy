package middleware

import "strings"

// Path represents a URI path, maybe with pattern characters.
type Path string

// Matches checks to see if other matches p.
//
// Path matching will probably not always be a direct
// comparison; this method assures that paths can be
// easily and consistently matched.
func (p Path) Matches(other string) bool {
	return strings.HasPrefix(string(p), other)
}
