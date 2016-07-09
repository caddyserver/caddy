package httpserver

import (
	"net/http"
	"strings"
)

// Path represents a URI path.
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

// PathMatcher is a Path RequestMatcher.
type PathMatcher string

// Match satisfies RequestMatcher.
func (p PathMatcher) Match(r *http.Request) bool {
	return Path(r.URL.Path).Matches(string(p))
}
