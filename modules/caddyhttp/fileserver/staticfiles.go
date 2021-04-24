// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fileserver

import (
	"bytes"
	"fmt"
	"html/template"
	weakrand "math/rand"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/encode"
	"go.uber.org/zap"
)

func init() {
	weakrand.Seed(time.Now().UnixNano())

	caddy.RegisterModule(FileServer{})
}

// FileServer implements a static file server responder for Caddy.
type FileServer struct {
	// The path to the root of the site. Default is `{http.vars.root}` if set,
	// or current working directory otherwise.
	Root string `json:"root,omitempty"`

	// A list of files or folders to hide; the file server will pretend as if
	// they don't exist. Accepts globular patterns like "*.ext" or "/foo/*/bar"
	// as well as placeholders. Because site roots can be dynamic, this list
	// uses file system paths, not request paths. To clarify, the base of
	// relative paths is the current working directory, NOT the site root.
	//
	// Entries without a path separator (`/` or `\` depending on OS) will match
	// any file or directory of that name regardless of its path. To hide only a
	// specific file with a name that may not be unique, always use a path
	// separator. For example, to hide all files or folder trees named "hidden",
	// put "hidden" in the list. To hide only ./hidden, put "./hidden" in the list.
	//
	// When possible, all paths are resolved to their absolute form before
	// comparisons are made. For maximum clarity and explictness, use complete,
	// absolute paths; or, for greater portability, use relative paths instead.
	Hide []string `json:"hide,omitempty"`

	// The names of files to try as index files if a folder is requested.
	IndexNames []string `json:"index_names,omitempty"`

	// Enables file listings if a directory was requested and no index
	// file is present.
	Browse *Browse `json:"browse,omitempty"`

	// Use redirects to enforce trailing slashes for directories, or to
	// remove trailing slash from URIs for files. Default is true.
	CanonicalURIs *bool `json:"canonical_uris,omitempty"`

	// Override the status code written when successfully serving a file.
	// Particularly useful when explicitly serving a file as display for
	// an error, like a 404 page. A placeholder may be used. By default,
	// the status code will typically be 200, or 206 for partial content.
	StatusCode caddyhttp.WeakString `json:"status_code,omitempty"`

	// If pass-thru mode is enabled and a requested file is not found,
	// it will invoke the next handler in the chain instead of returning
	// a 404 error. By default, this is false (disabled).
	PassThru bool `json:"pass_thru,omitempty"`

	// Selection of encoders to use to check for precompressed files.
	PrecompressedRaw caddy.ModuleMap `json:"precompressed,omitempty" caddy:"namespace=http.precompressed"`

	// If the client has no strong preference (q-factor), choose these encodings in order.
	// If no order specified here, the first encoding from the Accept-Encoding header
	// that both client and server support is used
	PrecompressedOrder []string `json:"precompressed_order,omitempty"`

	precompressors map[string]encode.Precompressed

	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (FileServer) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.file_server",
		New: func() caddy.Module { return new(FileServer) },
	}
}

// Provision sets up the static files responder.
func (fsrv *FileServer) Provision(ctx caddy.Context) error {
	fsrv.logger = ctx.Logger(fsrv)

	if fsrv.Root == "" {
		fsrv.Root = "{http.vars.root}"
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

	// for hide paths that are static (i.e. no placeholders), we can transform them into
	// absolute paths before the server starts for very slight performance improvement
	for i, h := range fsrv.Hide {
		if !strings.Contains(h, "{") && strings.Contains(h, separator) {
			if abs, err := filepath.Abs(h); err == nil {
				fsrv.Hide[i] = abs
			}
		}
	}

	mods, err := ctx.LoadModule(fsrv, "PrecompressedRaw")
	if err != nil {
		return fmt.Errorf("loading encoder modules: %v", err)
	}
	for modName, modIface := range mods.(map[string]interface{}) {
		p, ok := modIface.(encode.Precompressed)
		if !ok {
			return fmt.Errorf("module %s is not precompressor", modName)
		}
		ae := p.AcceptEncoding()
		if ae == "" {
			return fmt.Errorf("precompressor does not specify an Accept-Encoding value")
		}
		suffix := p.Suffix()
		if suffix == "" {
			return fmt.Errorf("precompressor does not specify a Suffix value")
		}
		if _, ok := fsrv.precompressors[ae]; ok {
			return fmt.Errorf("precompressor already added: %s", ae)
		}
		if fsrv.precompressors == nil {
			fsrv.precompressors = make(map[string]encode.Precompressed)
		}
		fsrv.precompressors[ae] = p
	}

	return nil
}

func (fsrv *FileServer) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

	filesToHide := fsrv.transformHidePaths(repl)

	root := repl.ReplaceAll(fsrv.Root, ".")
	filename := sanitizedPathJoin(root, r.URL.Path)

	fsrv.logger.Debug("sanitized path join",
		zap.String("site_root", root),
		zap.String("request_path", r.URL.Path),
		zap.String("result", filename))

	// get information about the file
	info, err := os.Stat(filename)
	if err != nil {
		err = mapDirOpenError(err, filename)
		if os.IsNotExist(err) {
			return fsrv.notFound(w, r, next)
		} else if os.IsPermission(err) {
			return caddyhttp.Error(http.StatusForbidden, err)
		}
		// TODO: treat this as resource exhaustion like with os.Open? Or unnecessary here?
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	// if the request mapped to a directory, see if
	// there is an index file we can serve
	var implicitIndexFile bool
	if info.IsDir() && len(fsrv.IndexNames) > 0 {
		for _, indexPage := range fsrv.IndexNames {
			indexPath := sanitizedPathJoin(filename, indexPage)
			if fileHidden(indexPath, filesToHide) {
				// pretend this file doesn't exist
				fsrv.logger.Debug("hiding index file",
					zap.String("filename", indexPath),
					zap.Strings("files_to_hide", filesToHide))
				continue
			}

			indexInfo, err := os.Stat(indexPath)
			if err != nil {
				continue
			}

			// don't rewrite the request path to append
			// the index file, because we might need to
			// do a canonical-URL redirect below based
			// on the URL as-is

			// we've chosen to use this index file,
			// so replace the last file info and path
			// with that of the index file
			info = indexInfo
			filename = indexPath
			implicitIndexFile = true
			fsrv.logger.Debug("located index file", zap.String("filename", filename))
			break
		}
	}

	// if still referencing a directory, delegate
	// to browse or return an error
	if info.IsDir() {
		fsrv.logger.Debug("no index file in directory",
			zap.String("path", filename),
			zap.Strings("index_filenames", fsrv.IndexNames))
		if fsrv.Browse != nil && !fileHidden(filename, filesToHide) {
			return fsrv.serveBrowse(root, filename, w, r, next)
		}
		return fsrv.notFound(w, r, next)
	}

	// one last check to ensure the file isn't hidden (we might
	// have changed the filename from when we last checked)
	if fileHidden(filename, filesToHide) {
		fsrv.logger.Debug("hiding file",
			zap.String("filename", filename),
			zap.Strings("files_to_hide", filesToHide))
		return fsrv.notFound(w, r, next)
	}

	// if URL canonicalization is enabled, we need to enforce trailing
	// slash convention: if a directory, trailing slash; if a file, no
	// trailing slash - not enforcing this can break relative hrefs
	// in HTML (see https://github.com/caddyserver/caddy/issues/2741)
	if fsrv.CanonicalURIs == nil || *fsrv.CanonicalURIs {
		if implicitIndexFile && !strings.HasSuffix(r.URL.Path, "/") {
			fsrv.logger.Debug("redirecting to canonical URI (adding trailing slash for directory)", zap.String("path", r.URL.Path))
			return redirect(w, r, r.URL.Path+"/")
		} else if !implicitIndexFile && strings.HasSuffix(r.URL.Path, "/") {
			fsrv.logger.Debug("redirecting to canonical URI (removing trailing slash for file)", zap.String("path", r.URL.Path))
			return redirect(w, r, r.URL.Path[:len(r.URL.Path)-1])
		}
	}

	var file *os.File

	// check for precompressed files
	for _, ae := range encode.AcceptedEncodings(r, fsrv.PrecompressedOrder) {
		precompress, ok := fsrv.precompressors[ae]
		if !ok {
			continue
		}
		compressedFilename := filename + precompress.Suffix()
		compressedInfo, err := os.Stat(compressedFilename)
		if err != nil || compressedInfo.IsDir() {
			fsrv.logger.Debug("precompressed file not accessible", zap.String("filename", compressedFilename), zap.Error(err))
			continue
		}
		fsrv.logger.Debug("opening compressed sidecar file", zap.String("filename", compressedFilename), zap.Error(err))
		file, err = fsrv.openFile(compressedFilename, w)
		if err != nil {
			fsrv.logger.Warn("opening precompressed file failed", zap.String("filename", compressedFilename), zap.Error(err))
			if caddyErr, ok := err.(caddyhttp.HandlerError); ok && caddyErr.StatusCode == http.StatusServiceUnavailable {
				return err
			}
			continue
		}
		defer file.Close()
		w.Header().Set("Content-Encoding", ae)
		w.Header().Del("Accept-Ranges")
		w.Header().Add("Vary", "Accept-Encoding")
		break
	}

	// no precompressed file found, use the actual file
	if file == nil {
		fsrv.logger.Debug("opening file", zap.String("filename", filename))

		// open the file
		file, err = fsrv.openFile(filename, w)
		if err != nil {
			if herr, ok := err.(caddyhttp.HandlerError); ok &&
				herr.StatusCode == http.StatusNotFound {
				return fsrv.notFound(w, r, next)
			}
			return err // error is already structured
		}
		defer file.Close()
	}

	// set the ETag - note that a conditional If-None-Match request is handled
	// by http.ServeContent below, which checks against this ETag value
	w.Header().Set("ETag", calculateEtag(info))

	if w.Header().Get("Content-Type") == "" {
		mtyp := mime.TypeByExtension(filepath.Ext(filename))
		if mtyp == "" {
			// do not allow Go to sniff the content-type; see
			// https://www.youtube.com/watch?v=8t8JYpt0egE
			// TODO: If we want a Content-Type, consider writing a default of application/octet-stream - this is secure but violates spec
			w.Header()["Content-Type"] = nil
		} else {
			w.Header().Set("Content-Type", mtyp)
		}
	}

	// if a status code override is configured, write the status code
	// before serving the file
	if codeStr := fsrv.StatusCode.String(); codeStr != "" {
		intVal, err := strconv.Atoi(repl.ReplaceAll(codeStr, ""))
		if err != nil {
			return caddyhttp.Error(http.StatusInternalServerError, err)
		}
		w.WriteHeader(intVal)
	}

	// if this handler exists in an error context (i.e. is
	// part of a handler chain that is supposed to handle
	// a previous error), we should set status code to the
	// one from the error instead of letting http.ServeContent
	// set the default (usually 200)
	if reqErr, ok := r.Context().Value(caddyhttp.ErrorCtxKey).(error); ok {
		statusCode := http.StatusInternalServerError
		if handlerErr, ok := reqErr.(caddyhttp.HandlerError); ok {
			if handlerErr.StatusCode > 0 {
				statusCode = handlerErr.StatusCode
			}
		}
		w.WriteHeader(statusCode)
	}

	// let the standard library do what it does best; note, however,
	// that errors generated by ServeContent are written immediately
	// to the response, so we cannot handle them (but errors there
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
			fsrv.logger.Debug("file not found", zap.String("filename", filename), zap.Error(err))
			return nil, caddyhttp.Error(http.StatusNotFound, err)
		} else if os.IsPermission(err) {
			fsrv.logger.Debug("permission denied", zap.String("filename", filename), zap.Error(err))
			return nil, caddyhttp.Error(http.StatusForbidden, err)
		}
		// maybe the server is under load and ran out of file descriptors?
		// have client wait arbitrary seconds to help prevent a stampede
		//nolint:gosec
		backoff := weakrand.Intn(maxBackoff-minBackoff) + minBackoff
		w.Header().Set("Retry-After", strconv.Itoa(backoff))
		fsrv.logger.Debug("retry after backoff", zap.String("filename", filename), zap.Int("backoff", backoff), zap.Error(err))
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

	parts := strings.Split(name, separator)
	for i := range parts {
		if parts[i] == "" {
			continue
		}
		fi, err := os.Stat(strings.Join(parts[:i+1], separator))
		if err != nil {
			return originalErr
		}
		if !fi.IsDir() {
			return os.ErrNotExist
		}
	}

	return originalErr
}

// transformHidePaths performs replacements for all the elements of fsrv.Hide and
// makes them absolute paths (if they contain a path separator), then returns a
// new list of the transformed values.
func (fsrv *FileServer) transformHidePaths(repl *caddy.Replacer) []string {
	hide := make([]string, len(fsrv.Hide))
	for i := range fsrv.Hide {
		hide[i] = repl.ReplaceAll(fsrv.Hide[i], "")
		if strings.Contains(hide[i], separator) {
			abs, err := filepath.Abs(hide[i])
			if err == nil {
				hide[i] = abs
			}
		}
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

	path := filepath.Join(root, filepath.Clean("/"+reqPath))

	// filepath.Join also cleans the path, and cleaning strips
	// the trailing slash, so we need to re-add it afterwards.
	// if the length is 1, then it's a path to the root,
	// and that should return ".", so we don't append the separator.
	if strings.HasSuffix(reqPath, "/") && len(reqPath) > 1 {
		path += separator
	}

	return path
}

// fileHidden returns true if filename is hidden according to the hide list.
// filename must be a relative or absolute file system path, not a request
// URI path. It is expected that all the paths in the hide list are absolute
// paths or are singular filenames (without a path separator).
func fileHidden(filename string, hide []string) bool {
	if len(hide) == 0 {
		return false
	}

	// all path comparisons use the complete absolute path if possible
	filenameAbs, err := filepath.Abs(filename)
	if err == nil {
		filename = filenameAbs
	}

	var components []string

	for _, h := range hide {
		if !strings.Contains(h, separator) {
			// if there is no separator in h, then we assume the user
			// wants to hide any files or folders that match that
			// name; thus we have to compare against each component
			// of the filename, e.g. hiding "bar" would hide "/bar"
			// as well as "/foo/bar/baz" but not "/barstool".
			if len(components) == 0 {
				components = strings.Split(filename, separator)
			}
			for _, c := range components {
				if hidden, _ := filepath.Match(h, c); hidden {
					return true
				}
			}
		} else if strings.HasPrefix(filename, h) {
			// if there is a separator in h, and filename is exactly
			// prefixed with h, then we can do a prefix match so that
			// "/foo" matches "/foo/bar" but not "/foobar".
			withoutPrefix := strings.TrimPrefix(filename, h)
			if strings.HasPrefix(withoutPrefix, separator) {
				return true
			}
		}

		// in the general case, a glob match will suffice
		if hidden, _ := filepath.Match(h, filename); hidden {
			return true
		}
	}

	return false
}

// notFound returns a 404 error or, if pass-thru is enabled,
// it calls the next handler in the chain.
func (fsrv *FileServer) notFound(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if fsrv.PassThru {
		return next.ServeHTTP(w, r)
	}
	return caddyhttp.Error(http.StatusNotFound, nil)
}

// calculateEtag produces a strong etag by default, although, for
// efficiency reasons, it does not actually consume the contents
// of the file to make a hash of all the bytes. ¯\_(ツ)_/¯
// Prefix the etag with "W/" to convert it into a weak etag.
// See: https://tools.ietf.org/html/rfc7232#section-2.3
func calculateEtag(d os.FileInfo) string {
	t := strconv.FormatInt(d.ModTime().Unix(), 36)
	s := strconv.FormatInt(d.Size(), 36)
	return `"` + t + s + `"`
}

func redirect(w http.ResponseWriter, r *http.Request, to string) error {
	for strings.HasPrefix(to, "//") {
		// prevent path-based open redirects
		to = strings.TrimPrefix(to, "/")
	}
	http.Redirect(w, r, to, http.StatusPermanentRedirect)
	return nil
}

var defaultIndexNames = []string{"index.html", "index.txt"}

var bufPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

const (
	minBackoff, maxBackoff = 2, 5
	separator              = string(filepath.Separator)
)

// Interface guards
var (
	_ caddy.Provisioner           = (*FileServer)(nil)
	_ caddyhttp.MiddlewareHandler = (*FileServer)(nil)
)
