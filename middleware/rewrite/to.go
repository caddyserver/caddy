package rewrite

import (
	"log"
	"net/http"
	"net/url"
	"strings"
)

// To attempts rewrite. It attempts to rewrite to first valid path
// or the last path if none of the paths are valid.
// Returns true if rewrite is successful and false otherwise.
func To(fs http.FileSystem, r *http.Request, to string) bool {
	tos := strings.Fields(to)
	replacer := newReplacer(r)

	// try each rewrite paths
	t := ""
	for _, v := range tos {
		t = replacer.Replace(v)
		if isValidFile(fs, t) {
			break
		}
	}

	// validate resulting path
	u, err := url.Parse(t)
	if err != nil {
		// Let the user know we got here. Rewrite is expected but
		// the resulting url is invalid.
		log.Printf("[ERROR] rewrite: resulting path '%v' is invalid. error: %v", t, err)
		return false
	}

	// take note of this rewrite for internal use by fastcgi
	// all we need is the URI, not full URL
	r.Header.Set(headerFieldName, r.URL.RequestURI())

	// perform rewrite
	r.URL.Path = u.Path
	if u.RawQuery != "" {
		// overwrite query string if present
		r.URL.RawQuery = u.RawQuery
	}
	if u.Fragment != "" {
		// overwrite fragment if present
		r.URL.Fragment = u.Fragment
	}

	return true
}

// isValidFile checks if file exists on the filesystem.
// if file ends with `/`, it is validated as a directory.
func isValidFile(fs http.FileSystem, file string) bool {
	f, err := fs.Open(file)
	if err != nil {
		return false
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return false
	}

	return strings.HasSuffix(file, "/") && stat.IsDir()
}
