package fileserver

import (
	"net/http"
	"os"
	"path/filepath"

	"bitbucket.org/lightcodelabs/caddy2"
	"bitbucket.org/lightcodelabs/caddy2/modules/caddyhttp"
)

func init() {
	caddy2.RegisterModule(caddy2.Module{
		Name: "http.matchers.file",
		New:  func() (interface{}, error) { return new(FileMatcher), nil },
	})
}

// FileMatcher is a matcher that can match requests
// based on the local file system.
// TODO: Not sure how to do this well; we'd need the ability to
// hide files, etc...
// TODO: Also consider a feature to match directory that
// contains a certain filename (use filepath.Glob), useful
// if wanting to map directory-URI requests where the dir
// has index.php to PHP backends, for example (although this
// can effectively be done with rehandling already)
type FileMatcher struct {
	Root  string   `json:"root"`
	Path  string   `json:"path"`
	Flags []string `json:"flags"`
}

// Match matches the request r against m.
func (m FileMatcher) Match(r *http.Request) bool {
	// TODO: sanitize path
	fullPath := filepath.Join(m.Root, m.Path)
	var match bool
	if len(m.Flags) > 0 {
		match = true
		fi, err := os.Stat(fullPath)
		for _, f := range m.Flags {
			switch f {
			case "EXIST":
				match = match && os.IsNotExist(err)
			case "DIR":
				match = match && err == nil && fi.IsDir()
			default:
				match = false
			}
		}
	}
	return match
}

// Interface guard
var _ caddyhttp.RequestMatcher = (*FileMatcher)(nil)
