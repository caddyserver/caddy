package fileserver

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

	"github.com/caddyserver/caddy2"
	"github.com/caddyserver/caddy2/modules/caddyhttp"
)

func init() {
	weakrand.Seed(time.Now().UnixNano())

	caddy2.RegisterModule(caddy2.Module{
		Name: "http.responders.file_server",
		New:  func() interface{} { return new(FileServer) },
	})
}

// FileServer implements a static file server responder for Caddy.
type FileServer struct {
	Root            string              `json:"root,omitempty"` // default is current directory
	Hide            []string            `json:"hide,omitempty"`
	IndexNames      []string            `json:"index_names,omitempty"`
	Files           []string            `json:"files,omitempty"` // all relative to the root; default is request URI path
	SelectionPolicy string              `json:"selection_policy,omitempty"`
	Rehandle        bool                `json:"rehandle,omitempty"` // issue a rehandle (internal redirect) if request is rewritten
	Fallback        caddyhttp.RouteList `json:"fallback,omitempty"`
	Browse          *Browse             `json:"browse,omitempty"`
	// TODO: Etag
	// TODO: Content negotiation
}

// Provision sets up the static files responder.
func (fsrv *FileServer) Provision(ctx caddy2.Context) error {
	if fsrv.Fallback != nil {
		err := fsrv.Fallback.Provision(ctx)
		if err != nil {
			return fmt.Errorf("setting up fallback routes: %v", err)
		}
	}

	if fsrv.IndexNames == nil {
		fsrv.IndexNames = defaultIndexNames
	}

	if fsrv.Browse != nil {
		var tpl *template.Template
		var err error
		if fsrv.Browse.TemplateFile != "" {
			tpl, err = template.ParseFiles(fsrv.Browse.TemplateFile)
			if err != nil {
				return fmt.Errorf("parsing browse template file: %v", err)
			}
		} else {
			tpl, err = template.New("default_listing").Parse(defaultBrowseTemplate)
			if err != nil {
				return fmt.Errorf("parsing default browse template: %v", err)
			}
		}
		fsrv.Browse.template = tpl
	}

	return nil
}

const (
	selectionPolicyFirstExisting = "first_existing"
	selectionPolicyLargestSize   = "largest_size"
	selectionPolicySmallestSize  = "smallest_size"
	selectionPolicyRecentlyMod   = "most_recently_modified"
)

// Validate ensures that sf has a valid configuration.
func (fsrv *FileServer) Validate() error {
	switch fsrv.SelectionPolicy {
	case "",
		selectionPolicyFirstExisting,
		selectionPolicyLargestSize,
		selectionPolicySmallestSize,
		selectionPolicyRecentlyMod:
	default:
		return fmt.Errorf("unknown selection policy %s", fsrv.SelectionPolicy)
	}
	return nil
}

func (fsrv *FileServer) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	repl := r.Context().Value(caddy2.ReplacerCtxKey).(caddy2.Replacer)

	filesToHide := fsrv.transformHidePaths(repl)

	// map the request to a filename
	pathBefore := r.URL.Path
	filename := fsrv.selectFile(r, repl, filesToHide)
	if filename == "" {
		// no files worked, so resort to fallback
		if fsrv.Fallback != nil {
			fallback, w := fsrv.Fallback.BuildCompositeRoute(w, r)
			return fallback.ServeHTTP(w, r)
		}
		return caddyhttp.Error(http.StatusNotFound, nil)
	}

	// if the ultimate destination has changed, submit
	// this request for a rehandling (internal redirect)
	// if configured to do so
	if r.URL.Path != pathBefore && fsrv.Rehandle {
		return caddyhttp.ErrRehandle
	}

	// get information about the file
	info, err := os.Stat(filename)
	if err != nil {
		err = mapDirOpenError(err, filename)
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
	if info.IsDir() && len(fsrv.IndexNames) > 0 {
		for _, indexPage := range fsrv.IndexNames {
			indexPath := sanitizedPathJoin(filename, indexPage)
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
			r.URL.Path = path.Join(r.URL.Path, indexPage)
			if fsrv.Rehandle {
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
		if fsrv.Browse != nil && !fileHidden(filename, filesToHide) {
			return fsrv.serveBrowse(filename, w, r)
		}
		return caddyhttp.Error(http.StatusNotFound, nil)
	}

	// TODO: content negotiation (brotli sidecar files, etc...)

	// one last check to ensure the file isn't hidden (we might
	// have changed the filename from when we last checked)
	if fileHidden(filename, filesToHide) {
		return caddyhttp.Error(http.StatusNotFound, nil)
	}

	// open the file
	file, err := fsrv.openFile(filename, w)
	if err != nil {
		return err
	}
	defer file.Close()

	// TODO: Etag

	// do not allow Go to sniff the content-type
	if w.Header().Get("Content-Type") == "" {
		w.Header()["Content-Type"] = nil
	}

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
func (fsrv *FileServer) openFile(filename string, w http.ResponseWriter) (*os.File, error) {
	file, err := os.Open(filename)
	if err != nil {
		err = mapDirOpenError(err, filename)
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

// mapDirOpenError maps the provided non-nil error from opening name
// to a possibly better non-nil error. In particular, it turns OS-specific errors
// about opening files in non-directories into os.ErrNotExist. See golang/go#18984.
// Adapted from the Go standard library; originally written by Nathaniel Caza.
// https://go-review.googlesource.com/c/go/+/36635/
// https://go-review.googlesource.com/c/go/+/36804/
func mapDirOpenError(originalErr error, name string) error {
	if os.IsNotExist(originalErr) || os.IsPermission(originalErr) {
		return originalErr
	}

	parts := strings.Split(name, string(filepath.Separator))
	for i := range parts {
		if parts[i] == "" {
			continue
		}
		fi, err := os.Stat(strings.Join(parts[:i+1], string(filepath.Separator)))
		if err != nil {
			return originalErr
		}
		if !fi.IsDir() {
			return os.ErrNotExist
		}
	}

	return originalErr
}

// transformHidePaths performs replacements for all the elements of
// fsrv.Hide and returns a new list of the transformed values.
func (fsrv *FileServer) transformHidePaths(repl caddy2.Replacer) []string {
	hide := make([]string, len(fsrv.Hide))
	for i := range fsrv.Hide {
		hide[i] = repl.ReplaceAll(fsrv.Hide[i], "")
	}
	return hide
}

// sanitizedPathJoin performs filepath.Join(root, reqPath) that
// is safe against directory traversal attacks. It uses logic
// similar to that in the Go standard library, specifically
// in the implementation of http.Dir. The root is assumed to
// be a trusted path, but reqPath is not.
func sanitizedPathJoin(root, reqPath string) string {
	// TODO: Caddy 1 uses this:
	// prevent absolute path access on Windows, e.g. http://localhost:5000/C:\Windows\notepad.exe
	// if runtime.GOOS == "windows" && len(reqPath) > 0 && filepath.IsAbs(reqPath[1:]) {
	// TODO.
	// }

	// TODO: whereas std lib's http.Dir.Open() uses this:
	// if filepath.Separator != '/' && strings.ContainsRune(name, filepath.Separator) {
	// 	return nil, errors.New("http: invalid character in file path")
	// }

	// TODO: see https://play.golang.org/p/oh77BiVQFti for another thing to consider

	if root == "" {
		root = "."
	}
	return filepath.Join(root, filepath.FromSlash(path.Clean("/"+reqPath)))
}

// selectFile uses the specified selection policy (or first_existing
// by default) to map the request r to a filename. The full path to
// the file is returned if one is found; otherwise, an empty string
// is returned.
func (fsrv *FileServer) selectFile(r *http.Request, repl caddy2.Replacer, filesToHide []string) string {
	root := repl.ReplaceAll(fsrv.Root, "")

	if fsrv.Files == nil {
		return sanitizedPathJoin(root, r.URL.Path)
	}

	switch fsrv.SelectionPolicy {
	case "", selectionPolicyFirstExisting:
		filesToHide := fsrv.transformHidePaths(repl)
		for _, f := range fsrv.Files {
			suffix := repl.ReplaceAll(f, "")
			fullpath := sanitizedPathJoin(root, suffix)
			if !fileHidden(fullpath, filesToHide) && fileExists(fullpath) {
				r.URL.Path = suffix
				return fullpath
			}
		}

	case selectionPolicyLargestSize:
		var largestSize int64
		var largestFilename string
		var largestSuffix string
		for _, f := range fsrv.Files {
			suffix := repl.ReplaceAll(f, "")
			fullpath := sanitizedPathJoin(root, suffix)
			if fileHidden(fullpath, filesToHide) {
				continue
			}
			info, err := os.Stat(fullpath)
			if err == nil && info.Size() > largestSize {
				largestSize = info.Size()
				largestFilename = fullpath
				largestSuffix = suffix
			}
		}
		r.URL.Path = largestSuffix
		return largestFilename

	case selectionPolicySmallestSize:
		var smallestSize int64
		var smallestFilename string
		var smallestSuffix string
		for _, f := range fsrv.Files {
			suffix := repl.ReplaceAll(f, "")
			fullpath := sanitizedPathJoin(root, suffix)
			if fileHidden(fullpath, filesToHide) {
				continue
			}
			info, err := os.Stat(fullpath)
			if err == nil && (smallestSize == 0 || info.Size() < smallestSize) {
				smallestSize = info.Size()
				smallestFilename = fullpath
				smallestSuffix = suffix
			}
		}
		r.URL.Path = smallestSuffix
		return smallestFilename

	case selectionPolicyRecentlyMod:
		var recentDate time.Time
		var recentFilename string
		var recentSuffix string
		for _, f := range fsrv.Files {
			suffix := repl.ReplaceAll(f, "")
			fullpath := sanitizedPathJoin(root, suffix)
			if fileHidden(fullpath, filesToHide) {
				continue
			}
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
var _ caddyhttp.Handler = (*FileServer)(nil)
