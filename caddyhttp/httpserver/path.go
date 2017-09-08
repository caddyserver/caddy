package httpserver

import (
	"net/http"
	"path"
	"strings"
)

// Path represents a URI path. It should usually be
// set to the value of a request path.
type Path string

// Matches checks to see if base matches p. The correct
// usage of this method sets p as the request path, and
// base as a Caddyfile (user-defined) rule path.
//
// Path matching will probably not always be a direct
// comparison; this method assures that paths can be
// easily and consistently matched.
//
// Multiple slashes are collapsed/merged. See issue #1859.
func (p Path) Matches(base string) bool {
	if base == "/" || base == "" {
		return true
	}

	// sanitize the paths for comparison, very important
	// (slightly lossy if the base path requires multiple
	// consecutive forward slashes, since those will be merged)
	pHasTrailingSlash := strings.HasSuffix(string(p), "/")
	baseHasTrailingSlash := strings.HasSuffix(base, "/")
	p = Path(path.Clean(string(p)))
	base = path.Clean(base)
	if pHasTrailingSlash {
		p += "/"
	}
	if baseHasTrailingSlash {
		base += "/"
	}

	if CaseSensitivePath {
		return strings.HasPrefix(string(p), base)
	}
	return strings.HasPrefix(strings.ToLower(string(p)), strings.ToLower(base))
}

// PathMatcher is a Path RequestMatcher.
type PathMatcher string

// Match satisfies RequestMatcher.
func (p PathMatcher) Match(r *http.Request) bool {
	return Path(r.URL.Path).Matches(string(p))
}
