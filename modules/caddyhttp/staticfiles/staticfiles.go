package staticfiles

import (
	"fmt"
	"html/template"
	weakrand "math/rand"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"bitbucket.org/lightcodelabs/caddy2"
	"bitbucket.org/lightcodelabs/caddy2/modules/caddyhttp"
)

func init() {
	weakrand.Seed(time.Now().UnixNano())

	caddy2.RegisterModule(caddy2.Module{
		Name: "http.responders.static_files",
		New:  func() (interface{}, error) { return new(StaticFiles), nil },
	})
}

// StaticFiles implements a static file server responder for Caddy.
type StaticFiles struct {
	Root            string              `json:"root"` // default is current directory
	Hide            []string            `json:"hide"`
	IndexNames      []string            `json:"index_names"`
	Files           []string            `json:"files"`    // all relative to the root; default is request URI path
	Rehandle        bool                `json:"rehandle"` // issue a rehandle (internal redirect) if request is rewritten
	SelectionPolicy string              `json:"selection_policy"`
	Fallback        caddyhttp.RouteList `json:"fallback"`
	Browse          *Browse             `json:"browse"`
	// TODO: Etag
	// TODO: Content negotiation
}

// Provision sets up the static files responder.
func (sf *StaticFiles) Provision(ctx caddy2.Context) error {
	if sf.Fallback != nil {
		err := sf.Fallback.Provision(ctx)
		if err != nil {
			return fmt.Errorf("setting up fallback routes: %v", err)
		}
	}

	if sf.IndexNames == nil {
		sf.IndexNames = defaultIndexNames
	}

	if sf.Browse != nil {
		var tpl *template.Template
		var err error
		if sf.Browse.TemplateFile != "" {
			tpl, err = template.ParseFiles(sf.Browse.TemplateFile)
			if err != nil {
				return fmt.Errorf("parsing browse template file: %v", err)
			}
		} else {
			tpl, err = template.New("default_listing").Parse(defaultBrowseTemplate)
			if err != nil {
				return fmt.Errorf("parsing default browse template: %v", err)
			}
		}
		sf.Browse.template = tpl
	}

	return nil
}

// Validate ensures that sf has a valid configuration.
func (sf *StaticFiles) Validate() error {
	switch sf.SelectionPolicy {
	case "",
		"first_existing",
		"largest_size",
		"smallest_size",
		"most_recently_modified":
	default:
		return fmt.Errorf("unknown selection policy %s", sf.SelectionPolicy)
	}
	return nil
}

func (sf *StaticFiles) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	// TODO: Prevent directory traversal, see https://play.golang.org/p/oh77BiVQFti

	// TODO: Still needed?
	// // Prevent absolute path access on Windows, e.g.: http://localhost:5000/C:\Windows\notepad.exe
	// // TODO: does stdlib http.Dir handle this? see first check of http.Dir.Open()...
	// if runtime.GOOS == "windows" && len(reqPath) > 0 && filepath.IsAbs(reqPath[1:]) {
	// 	return caddyhttp.Error(http.StatusNotFound, fmt.Errorf("request path was absolute"))
	// }

	repl := r.Context().Value(caddy2.ReplacerCtxKey).(caddy2.Replacer)

	// map the request to a filename
	pathBefore := r.URL.Path
	filename := sf.selectFile(r, repl)
	if filename == "" {
		// no files worked, so resort to fallback
		if sf.Fallback != nil {
			fallback := sf.Fallback.BuildCompositeRoute(w, r)
			return fallback.ServeHTTP(w, r)
		}
		return caddyhttp.Error(http.StatusNotFound, nil)
	}

	// if the ultimate destination has changed, submit
	// this request for a rehandling (internal redirect)
	// if configured to do so
	// TODO: double check this against https://docs.nginx.com/nginx/admin-guide/web-server/serving-static-content/
	if r.URL.Path != pathBefore && sf.Rehandle {
		return caddyhttp.ErrRehandle
	}

	// get information about the file
	info, err := os.Stat(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return caddyhttp.Error(http.StatusNotFound, err)
		} else if os.IsPermission(err) {
			return caddyhttp.Error(http.StatusForbidden, err)
		}
		// TODO: treat this as resource exhaustion like with os.Open? Or unnecessary here?
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	// if the request mapped to a directory, see if
	// there is an index file we can serve
	if info.IsDir() && len(sf.IndexNames) > 0 {
		filesToHide := sf.transformHidePaths(repl)

		for _, indexPage := range sf.IndexNames {
			indexPath := path.Join(filename, indexPage)
			if fileHidden(indexPath, filesToHide) {
				// pretend this file doesn't exist
				continue
			}

			indexInfo, err := os.Stat(indexPath)
			if err != nil {
				continue
			}

			// we found an index file that might work,
			// so rewrite the request path and, if
			// configured, do an internal redirect
			// TODO: I don't know if the logic for rewriting
			// the URL here is the right logic
			r.URL.Path = path.Join(r.URL.Path, indexPage)
			if sf.Rehandle {
				return caddyhttp.ErrRehandle
			}

			info = indexInfo
			filename = indexPath
			break
		}
	}

	// if still referencing a directory, delegate
	// to browse or return an error
	if info.IsDir() {
		if sf.Browse != nil {
			return sf.serveBrowse(filename, w, r)
		}
		return caddyhttp.Error(http.StatusNotFound, nil)
	}

	// open the file
	file, err := sf.openFile(filename, w)
	if err != nil {
		return err
	}
	defer file.Close()

	// TODO: Etag?

	// TODO: content negotiation? (brotli sidecar files, etc...)

	// let the standard library do what it does best; note, however,
	// that errors generated by ServeContent are written immediately
	// to the response, so we cannot handle them (but errors here
	// are rare)
	http.ServeContent(w, r, info.Name(), info.ModTime(), file)

	return nil
}

// openFile opens the file at the given filename. If there was an error,
// the response is configured to inform the client how to best handle it
// and a well-described handler error is returned (do not wrap the
// returned error value).
func (sf *StaticFiles) openFile(filename string, w http.ResponseWriter) (*os.File, error) {
	file, err := os.Open(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, caddyhttp.Error(http.StatusNotFound, err)
		} else if os.IsPermission(err) {
			return nil, caddyhttp.Error(http.StatusForbidden, err)
		}
		// maybe the server is under load and ran out of file descriptors?
		// have client wait arbitrary seconds to help prevent a stampede
		backoff := weakrand.Intn(maxBackoff-minBackoff) + minBackoff
		w.Header().Set("Retry-After", strconv.Itoa(backoff))
		return nil, caddyhttp.Error(http.StatusServiceUnavailable, err)
	}
	return file, nil
}

// transformHidePaths performs replacements for all the elements of
// sf.Hide and returns a new list of the transformed values.
func (sf *StaticFiles) transformHidePaths(repl caddy2.Replacer) []string {
	hide := make([]string, len(sf.Hide))
	for i := range sf.Hide {
		hide[i] = repl.ReplaceAll(sf.Hide[i], "")
	}
	return hide
}

// selectFile uses the specified selection policy (or first_existing
// by default) to map the request r to a filename. The full path to
// the file is returned if one is found; otherwise, an empty string
// is returned.
func (sf *StaticFiles) selectFile(r *http.Request, repl caddy2.Replacer) string {
	root := repl.ReplaceAll(sf.Root, "")
	if root == "" {
		root = "."
	}

	if sf.Files == nil {
		return filepath.Join(root, r.URL.Path)
	}

	switch sf.SelectionPolicy {
	// TODO: Make these policy names constants
	case "", "first_existing":
		filesToHide := sf.transformHidePaths(repl)
		for _, f := range sf.Files {
			suffix := repl.ReplaceAll(f, "")
			// TODO: sanitize path
			fullpath := filepath.Join(root, suffix)
			if !fileHidden(fullpath, filesToHide) && fileExists(fullpath) {
				r.URL.Path = suffix
				return fullpath
			}
		}

	case "largest_size":
		var largestSize int64
		var largestFilename string
		var largestSuffix string
		for _, f := range sf.Files {
			suffix := repl.ReplaceAll(f, "")
			// TODO: sanitize path
			fullpath := filepath.Join(root, suffix)
			info, err := os.Stat(fullpath)
			if err == nil && info.Size() > largestSize {
				largestSize = info.Size()
				largestFilename = fullpath
				largestSuffix = suffix
			}
		}
		r.URL.Path = largestSuffix
		return largestFilename

	case "smallest_size":
		var smallestSize int64
		var smallestFilename string
		var smallestSuffix string
		for _, f := range sf.Files {
			suffix := repl.ReplaceAll(f, "")
			// TODO: sanitize path
			fullpath := filepath.Join(root, suffix)
			info, err := os.Stat(fullpath)
			if err == nil && (smallestSize == 0 || info.Size() < smallestSize) {
				smallestSize = info.Size()
				smallestFilename = fullpath
				smallestSuffix = suffix
			}
		}
		r.URL.Path = smallestSuffix
		return smallestFilename

	case "most_recently_modified":
		var recentDate time.Time
		var recentFilename string
		var recentSuffix string
		for _, f := range sf.Files {
			suffix := repl.ReplaceAll(f, "")
			// TODO: sanitize path
			fullpath := filepath.Join(root, suffix)
			info, err := os.Stat(fullpath)
			if err == nil &&
				(recentDate.IsZero() || info.ModTime().After(recentDate)) {
				recentDate = info.ModTime()
				recentFilename = fullpath
				recentSuffix = suffix
			}
		}
		r.URL.Path = recentSuffix
		return recentFilename
	}

	return ""
}

// fileExists returns true if file exists.
func fileExists(file string) bool {
	_, err := os.Stat(file)
	return !os.IsNotExist(err)
}

// fileHidden returns true if filename is hidden
// according to the hide list.
func fileHidden(filename string, hide []string) bool {
	nameOnly := filepath.Base(filename)
	sep := string(filepath.Separator)

	// see if file is hidden
	for _, h := range hide {
		// assuming h is a glob/shell-like pattern,
		// use it to compare the whole file path;
		// but if there is no separator in h, then
		// just compare against the file's name
		compare := filename
		if !strings.Contains(h, sep) {
			compare = nameOnly
		}

		hidden, err := filepath.Match(h, compare)
		if err != nil {
			// malformed pattern; fallback by checking prefix
			if strings.HasPrefix(filename, h) {
				return true
			}
		}
		if hidden {
			// file name or path matches hide pattern
			return true
		}
	}

	return false
}

var defaultIndexNames = []string{"index.html"}

const minBackoff, maxBackoff = 2, 5

// Interface guard
var _ caddyhttp.Handler = (*StaticFiles)(nil)
