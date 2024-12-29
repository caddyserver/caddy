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
	"errors"
	"fmt"
	"io"
	"io/fs"
	weakrand "math/rand"
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/encode"
)

func init() {
	caddy.RegisterModule(FileServer{})
}

// FileServer implements a handler that serves static files.
//
// The path of the file to serve is constructed by joining the site root
// and the sanitized request path. Any and all files within the root and
// links with targets outside the site root may therefore be accessed.
// For example, with a site root of `/www`, requests to `/foo/bar.txt`
// will serve the file at `/www/foo/bar.txt`.
//
// The request path is sanitized using the Go standard library's
// path.Clean() function (https://pkg.go.dev/path#Clean) before being
// joined to the root. Request paths must be valid and well-formed.
//
// For requests that access directories instead of regular files,
// Caddy will attempt to serve an index file if present. For example,
// a request to `/dir/` will attempt to serve `/dir/index.html` if
// it exists. The index file names to try are configurable. If a
// requested directory does not have an index file, Caddy writes a
// 404 response. Alternatively, file browsing can be enabled with
// the "browse" parameter which shows a list of files when directories
// are requested if no index file is present. If "browse" is enabled,
// Caddy may serve a JSON array of the directory listing when the `Accept`
// header mentions `application/json` with the following structure:
//
//	[{
//		"name": "",
//		"size": 0,
//		"url": "",
//		"mod_time": "",
//		"mode": 0,
//		"is_dir": false,
//		"is_symlink": false
//	}]
//
// with the `url` being relative to the request path and `mod_time` in the RFC 3339 format
// with sub-second precision. For any other value for the `Accept` header, the
// respective browse template is executed with `Content-Type: text/html`.
//
// By default, this handler will canonicalize URIs so that requests to
// directories end with a slash, but requests to regular files do not.
// This is enforced with HTTP redirects automatically and can be disabled.
// Canonicalization redirects are not issued, however, if a URI rewrite
// modified the last component of the path (the filename).
//
// This handler sets the Etag and Last-Modified headers for static files.
// It does not perform MIME sniffing to determine Content-Type based on
// contents, but does use the extension (if known); see the Go docs for
// details: https://pkg.go.dev/mime#TypeByExtension
//
// The file server properly handles requests with If-Match,
// If-Unmodified-Since, If-Modified-Since, If-None-Match, Range, and
// If-Range headers. It includes the file's modification time in the
// Last-Modified header of the response.
type FileServer struct {
	// The file system implementation to use. By default, Caddy uses the local
	// disk file system.
	//
	// if a non default filesystem is used, it must be first be registered in the globals section.
	FileSystem string `json:"fs,omitempty"`

	// The path to the root of the site. Default is `{http.vars.root}` if set,
	// or current working directory otherwise. This should be a trusted value.
	//
	// Note that a site root is not a sandbox. Although the file server does
	// sanitize the request URI to prevent directory traversal, files (including
	// links) within the site root may be directly accessed based on the request
	// path. Files and folders within the root should be secure and trustworthy.
	Root string `json:"root,omitempty"`

	// A list of files or folders to hide; the file server will pretend as if
	// they don't exist. Accepts globular patterns like `*.ext` or `/foo/*/bar`
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
	// Default: index.html, index.txt.
	IndexNames []string `json:"index_names,omitempty"`

	// Enables file listings if a directory was requested and no index
	// file is present.
	Browse *Browse `json:"browse,omitempty"`

	// Use redirects to enforce trailing slashes for directories, or to
	// remove trailing slash from URIs for files. Default is true.
	//
	// Canonicalization will not happen if the last element of the request's
	// path (the filename) is changed in an internal rewrite, to avoid
	// clobbering the explicit rewrite with implicit behavior.
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
	precompressors     map[string]encode.Precompressed

	// List of file extensions to try to read Etags from.
	// If set, file Etags will be read from sidecar files
	// with any of these suffixes, instead of generating
	// our own Etag.
	EtagFileExtensions []string `json:"etag_file_extensions,omitempty"`

	fsmap caddy.FileSystems

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
	fsrv.logger = ctx.Logger()

	fsrv.fsmap = ctx.Filesystems()

	if fsrv.FileSystem == "" {
		fsrv.FileSystem = "{http.vars.fs}"
	}

	if fsrv.Root == "" {
		fsrv.Root = "{http.vars.root}"
	}

	if fsrv.IndexNames == nil {
		fsrv.IndexNames = defaultIndexNames
	}

	// for hide paths that are static (i.e. no placeholders), we can transform them into
	// absolute paths before the server starts for very slight performance improvement
	for i, h := range fsrv.Hide {
		if !strings.Contains(h, "{") && strings.Contains(h, separator) {
			if abs, err := caddy.FastAbs(h); err == nil {
				fsrv.Hide[i] = abs
			}
		}
	}

	// support precompressed sidecar files
	mods, err := ctx.LoadModule(fsrv, "PrecompressedRaw")
	if err != nil {
		return fmt.Errorf("loading encoder modules: %v", err)
	}
	for modName, modIface := range mods.(map[string]any) {
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

	if fsrv.Browse != nil {
		// check sort options
		for idx, sortOption := range fsrv.Browse.SortOptions {
			switch idx {
			case 0:
				if sortOption != sortByName && sortOption != sortByNameDirFirst && sortOption != sortBySize && sortOption != sortByTime {
					return fmt.Errorf("the first option must be one of the following: %s, %s, %s, %s, but got %s", sortByName, sortByNameDirFirst, sortBySize, sortByTime, sortOption)
				}
			case 1:
				if sortOption != sortOrderAsc && sortOption != sortOrderDesc {
					return fmt.Errorf("the second option must be one of the following: %s, %s, but got %s", sortOrderAsc, sortOrderDesc, sortOption)
				}
			default:
				return fmt.Errorf("only max 2 sort options are allowed, but got %d", idx+1)
			}
		}
	}

	return nil
}

func (fsrv *FileServer) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

	if runtime.GOOS == "windows" {
		// reject paths with Alternate Data Streams (ADS)
		if strings.Contains(r.URL.Path, ":") {
			return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("illegal ADS path"))
		}
		// reject paths with "8.3" short names
		trimmedPath := strings.TrimRight(r.URL.Path, ". ") // Windows ignores trailing dots and spaces, sigh
		if len(path.Base(trimmedPath)) <= 12 && strings.Contains(trimmedPath, "~") {
			return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("illegal short name"))
		}
		// both of those could bypass file hiding or possibly leak information even if the file is not hidden
	}

	filesToHide := fsrv.transformHidePaths(repl)

	root := repl.ReplaceAll(fsrv.Root, ".")
	fsName := repl.ReplaceAll(fsrv.FileSystem, "")

	fileSystem, ok := fsrv.fsmap.Get(fsName)
	if !ok {
		return caddyhttp.Error(http.StatusNotFound, fmt.Errorf("filesystem not found"))
	}

	// remove any trailing `/` as it breaks fs.ValidPath() in the stdlib
	filename := strings.TrimSuffix(caddyhttp.SanitizedPathJoin(root, r.URL.Path), "/")

	if c := fsrv.logger.Check(zapcore.DebugLevel, "sanitized path join"); c != nil {
		c.Write(
			zap.String("site_root", root),
			zap.String("fs", fsName),
			zap.String("request_path", r.URL.Path),
			zap.String("result", filename),
		)
	}

	// get information about the file
	info, err := fs.Stat(fileSystem, filename)
	if err != nil {
		err = fsrv.mapDirOpenError(fileSystem, err, filename)
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, fs.ErrInvalid) {
			return fsrv.notFound(w, r, next)
		} else if errors.Is(err, fs.ErrPermission) {
			return caddyhttp.Error(http.StatusForbidden, err)
		}
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	// if the request mapped to a directory, see if
	// there is an index file we can serve
	var implicitIndexFile bool
	if info.IsDir() && len(fsrv.IndexNames) > 0 {
		for _, indexPage := range fsrv.IndexNames {
			indexPage := repl.ReplaceAll(indexPage, "")
			indexPath := caddyhttp.SanitizedPathJoin(filename, indexPage)
			if fileHidden(indexPath, filesToHide) {
				// pretend this file doesn't exist
				if c := fsrv.logger.Check(zapcore.DebugLevel, "hiding index file"); c != nil {
					c.Write(
						zap.String("filename", indexPath),
						zap.Strings("files_to_hide", filesToHide),
					)
				}
				continue
			}

			indexInfo, err := fs.Stat(fileSystem, indexPath)
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
			if c := fsrv.logger.Check(zapcore.DebugLevel, "located index file"); c != nil {
				c.Write(zap.String("filename", filename))
			}
			break
		}
	}

	// if still referencing a directory, delegate
	// to browse or return an error
	if info.IsDir() {
		if c := fsrv.logger.Check(zapcore.DebugLevel, "no index file in directory"); c != nil {
			c.Write(
				zap.String("path", filename),
				zap.Strings("index_filenames", fsrv.IndexNames),
			)
		}
		if fsrv.Browse != nil && !fileHidden(filename, filesToHide) {
			return fsrv.serveBrowse(fileSystem, root, filename, w, r, next)
		}
		return fsrv.notFound(w, r, next)
	}

	// one last check to ensure the file isn't hidden (we might
	// have changed the filename from when we last checked)
	if fileHidden(filename, filesToHide) {
		if c := fsrv.logger.Check(zapcore.DebugLevel, "hiding file"); c != nil {
			c.Write(
				zap.String("filename", filename),
				zap.Strings("files_to_hide", filesToHide),
			)
		}
		return fsrv.notFound(w, r, next)
	}

	// if URL canonicalization is enabled, we need to enforce trailing
	// slash convention: if a directory, trailing slash; if a file, no
	// trailing slash - not enforcing this can break relative hrefs
	// in HTML (see https://github.com/caddyserver/caddy/issues/2741)
	if fsrv.CanonicalURIs == nil || *fsrv.CanonicalURIs {
		// Only redirect if the last element of the path (the filename) was not
		// rewritten; if the admin wanted to rewrite to the canonical path, they
		// would have, and we have to be very careful not to introduce unwanted
		// redirects and especially redirect loops!
		// See https://github.com/caddyserver/caddy/issues/4205.
		origReq := r.Context().Value(caddyhttp.OriginalRequestCtxKey).(http.Request)
		if path.Base(origReq.URL.Path) == path.Base(r.URL.Path) {
			if implicitIndexFile && !strings.HasSuffix(origReq.URL.Path, "/") {
				to := origReq.URL.Path + "/"
				if c := fsrv.logger.Check(zapcore.DebugLevel, "redirecting to canonical URI (adding trailing slash for directory"); c != nil {
					c.Write(
						zap.String("from_path", origReq.URL.Path),
						zap.String("to_path", to),
					)
				}
				return redirect(w, r, to)
			} else if !implicitIndexFile && strings.HasSuffix(origReq.URL.Path, "/") {
				to := origReq.URL.Path[:len(origReq.URL.Path)-1]
				if c := fsrv.logger.Check(zapcore.DebugLevel, "redirecting to canonical URI (removing trailing slash for file"); c != nil {
					c.Write(
						zap.String("from_path", origReq.URL.Path),
						zap.String("to_path", to),
					)
				}
				return redirect(w, r, to)
			}
		}
	}

	var file fs.File
	respHeader := w.Header()

	// etag is usually unset, but if the user knows what they're doing, let them override it
	etag := respHeader.Get("Etag")

	// static file responses are often compressed, either on-the-fly
	// or with precompressed sidecar files; in any case, the headers
	// should contain "Vary: Accept-Encoding" even when not compressed
	// so caches can craft a reliable key (according to REDbot results)
	// see #5849
	respHeader.Add("Vary", "Accept-Encoding")

	// check for precompressed files
	for _, ae := range encode.AcceptedEncodings(r, fsrv.PrecompressedOrder) {
		precompress, ok := fsrv.precompressors[ae]
		if !ok {
			continue
		}
		compressedFilename := filename + precompress.Suffix()
		compressedInfo, err := fs.Stat(fileSystem, compressedFilename)
		if err != nil || compressedInfo.IsDir() {
			if c := fsrv.logger.Check(zapcore.DebugLevel, "precompressed file not accessible"); c != nil {
				c.Write(zap.String("filename", compressedFilename), zap.Error(err))
			}
			continue
		}
		if c := fsrv.logger.Check(zapcore.DebugLevel, "opening compressed sidecar file"); c != nil {
			c.Write(zap.String("filename", compressedFilename), zap.Error(err))
		}
		file, err = fsrv.openFile(fileSystem, compressedFilename, w)
		if err != nil {
			if c := fsrv.logger.Check(zapcore.WarnLevel, "opening precompressed file failed"); c != nil {
				c.Write(zap.String("filename", compressedFilename), zap.Error(err))
			}
			if caddyErr, ok := err.(caddyhttp.HandlerError); ok && caddyErr.StatusCode == http.StatusServiceUnavailable {
				return err
			}
			file = nil
			continue
		}
		defer file.Close()
		respHeader.Set("Content-Encoding", ae)
		respHeader.Del("Accept-Ranges")

		// try to get the etag from pre computed files if an etag suffix list was provided
		if etag == "" && fsrv.EtagFileExtensions != nil {
			etag, err = fsrv.getEtagFromFile(fileSystem, compressedFilename)
			if err != nil {
				return err
			}
		}

		// don't assign info = compressedInfo because sidecars are kind
		// of transparent; however we do need to set the Etag:
		// https://caddy.community/t/gzipped-sidecar-file-wrong-same-etag/16793
		if etag == "" {
			etag = calculateEtag(compressedInfo)
		}

		break
	}

	// no precompressed file found, use the actual file
	if file == nil {
		if c := fsrv.logger.Check(zapcore.DebugLevel, "opening file"); c != nil {
			c.Write(zap.String("filename", filename))
		}

		// open the file
		file, err = fsrv.openFile(fileSystem, filename, w)
		if err != nil {
			if herr, ok := err.(caddyhttp.HandlerError); ok &&
				herr.StatusCode == http.StatusNotFound {
				return fsrv.notFound(w, r, next)
			}
			return err // error is already structured
		}
		defer file.Close()
		// try to get the etag from pre computed files if an etag suffix list was provided
		if etag == "" && fsrv.EtagFileExtensions != nil {
			etag, err = fsrv.getEtagFromFile(fileSystem, filename)
			if err != nil {
				return err
			}
		}
		if etag == "" {
			etag = calculateEtag(info)
		}
	}

	// at this point, we're serving a file; Go std lib supports only
	// GET and HEAD, which is sensible for a static file server - reject
	// any other methods (see issue #5166)
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		// if we're in an error context, then it doesn't make sense
		// to repeat the error; just continue because we're probably
		// trying to write an error page response (see issue #5703)
		if _, ok := r.Context().Value(caddyhttp.ErrorCtxKey).(error); !ok {
			respHeader.Add("Allow", "GET, HEAD")
			return caddyhttp.Error(http.StatusMethodNotAllowed, nil)
		}
	}

	// set the Etag - note that a conditional If-None-Match request is handled
	// by http.ServeContent below, which checks against this Etag value
	if etag != "" {
		respHeader.Set("Etag", etag)
	}

	if respHeader.Get("Content-Type") == "" {
		mtyp := mime.TypeByExtension(filepath.Ext(filename))
		if mtyp == "" {
			// do not allow Go to sniff the content-type; see https://www.youtube.com/watch?v=8t8JYpt0egE
			respHeader["Content-Type"] = nil
		} else {
			respHeader.Set("Content-Type", mtyp)
		}
	}

	var statusCodeOverride int

	// if this handler exists in an error context (i.e. is part of a
	// handler chain that is supposed to handle a previous error),
	// we should set status code to the one from the error instead
	// of letting http.ServeContent set the default (usually 200)
	if reqErr, ok := r.Context().Value(caddyhttp.ErrorCtxKey).(error); ok {
		statusCodeOverride = http.StatusInternalServerError
		if handlerErr, ok := reqErr.(caddyhttp.HandlerError); ok {
			if handlerErr.StatusCode > 0 {
				statusCodeOverride = handlerErr.StatusCode
			}
		}
	}

	// if a status code override is configured, run the replacer on it
	if codeStr := fsrv.StatusCode.String(); codeStr != "" {
		statusCodeOverride, err = strconv.Atoi(repl.ReplaceAll(codeStr, ""))
		if err != nil {
			return caddyhttp.Error(http.StatusInternalServerError, err)
		}
	}

	// if we do have an override from the previous two parts, then
	// we wrap the response writer to intercept the WriteHeader call
	if statusCodeOverride > 0 {
		w = statusOverrideResponseWriter{ResponseWriter: w, code: statusCodeOverride}
	}

	// let the standard library do what it does best; note, however,
	// that errors generated by ServeContent are written immediately
	// to the response, so we cannot handle them (but errors there
	// are rare)
	http.ServeContent(w, r, info.Name(), info.ModTime(), file.(io.ReadSeeker))

	return nil
}

// openFile opens the file at the given filename. If there was an error,
// the response is configured to inform the client how to best handle it
// and a well-described handler error is returned (do not wrap the
// returned error value).
func (fsrv *FileServer) openFile(fileSystem fs.FS, filename string, w http.ResponseWriter) (fs.File, error) {
	file, err := fileSystem.Open(filename)
	if err != nil {
		err = fsrv.mapDirOpenError(fileSystem, err, filename)
		if errors.Is(err, fs.ErrNotExist) {
			if c := fsrv.logger.Check(zapcore.DebugLevel, "file not found"); c != nil {
				c.Write(zap.String("filename", filename), zap.Error(err))
			}
			return nil, caddyhttp.Error(http.StatusNotFound, err)
		} else if errors.Is(err, fs.ErrPermission) {
			if c := fsrv.logger.Check(zapcore.DebugLevel, "permission denied"); c != nil {
				c.Write(zap.String("filename", filename), zap.Error(err))
			}
			return nil, caddyhttp.Error(http.StatusForbidden, err)
		}
		// maybe the server is under load and ran out of file descriptors?
		// have client wait arbitrary seconds to help prevent a stampede
		//nolint:gosec
		backoff := weakrand.Intn(maxBackoff-minBackoff) + minBackoff
		w.Header().Set("Retry-After", strconv.Itoa(backoff))
		if c := fsrv.logger.Check(zapcore.DebugLevel, "retry after backoff"); c != nil {
			c.Write(zap.String("filename", filename), zap.Int("backoff", backoff), zap.Error(err))
		}
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
func (fsrv *FileServer) mapDirOpenError(fileSystem fs.FS, originalErr error, name string) error {
	if errors.Is(originalErr, fs.ErrNotExist) || errors.Is(originalErr, fs.ErrPermission) {
		return originalErr
	}

	parts := strings.Split(name, separator)
	for i := range parts {
		if parts[i] == "" {
			continue
		}
		fi, err := fs.Stat(fileSystem, strings.Join(parts[:i+1], separator))
		if err != nil {
			return originalErr
		}
		if !fi.IsDir() {
			return fs.ErrNotExist
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
			abs, err := caddy.FastAbs(hide[i])
			if err == nil {
				hide[i] = abs
			}
		}
	}
	return hide
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
	filenameAbs, err := caddy.FastAbs(filename)
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

// calculateEtag computes an entity tag using a strong validator
// without consuming the contents of the file. It requires the
// file info contain the correct size and modification time.
// It strives to implement the semantics regarding ETags as defined
// by RFC 9110 section 8.8.3 and 8.8.1. See
// https://www.rfc-editor.org/rfc/rfc9110.html#section-8.8.3.
//
// As our implementation uses file modification timestamp and size,
// note the following from RFC 9110 section 8.8.1: "A representation's
// modification time, if defined with only one-second resolution,
// might be a weak validator if it is possible for the representation to
// be modified twice during a single second and retrieved between those
// modifications." The ext4 file system, which underpins the vast majority
// of Caddy deployments, stores mod times with millisecond precision,
// which we consider precise enough to qualify as a strong validator.
func calculateEtag(d os.FileInfo) string {
	mtime := d.ModTime()
	if mtimeUnix := mtime.Unix(); mtimeUnix == 0 || mtimeUnix == 1 {
		return "" // not useful anyway; see issue #5548
	}
	var sb strings.Builder
	sb.WriteRune('"')
	sb.WriteString(strconv.FormatInt(mtime.UnixNano(), 36))
	sb.WriteString(strconv.FormatInt(d.Size(), 36))
	sb.WriteRune('"')
	return sb.String()
}

// Finds the first corresponding etag file for a given file in the file system and return its content
func (fsrv *FileServer) getEtagFromFile(fileSystem fs.FS, filename string) (string, error) {
	for _, suffix := range fsrv.EtagFileExtensions {
		etagFilename := filename + suffix
		etag, err := fs.ReadFile(fileSystem, etagFilename)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return "", fmt.Errorf("cannot read etag from file %s: %v", etagFilename, err)
		}

		// Etags should not contain newline characters
		etag = bytes.ReplaceAll(etag, []byte("\n"), []byte{})

		return string(etag), nil
	}
	return "", nil
}

// redirect performs a redirect to a given path. The 'toPath' parameter
// MUST be solely a path, and MUST NOT include a query.
func redirect(w http.ResponseWriter, r *http.Request, toPath string) error {
	for strings.HasPrefix(toPath, "//") {
		// prevent path-based open redirects
		toPath = strings.TrimPrefix(toPath, "/")
	}
	// preserve the query string if present
	if r.URL.RawQuery != "" {
		toPath += "?" + r.URL.RawQuery
	}
	http.Redirect(w, r, toPath, http.StatusPermanentRedirect)
	return nil
}

// statusOverrideResponseWriter intercepts WriteHeader calls
// to instead write the HTTP status code we want instead
// of the one http.ServeContent will use by default (usually 200)
type statusOverrideResponseWriter struct {
	http.ResponseWriter
	code int
}

// WriteHeader intercepts calls by the stdlib to WriteHeader
// to instead write the HTTP status code we want.
func (wr statusOverrideResponseWriter) WriteHeader(int) {
	wr.ResponseWriter.WriteHeader(wr.code)
}

// Unwrap returns the underlying ResponseWriter, necessary for
// http.ResponseController to work correctly.
func (wr statusOverrideResponseWriter) Unwrap() http.ResponseWriter {
	return wr.ResponseWriter
}

var defaultIndexNames = []string{"index.html", "index.txt"}

const (
	minBackoff, maxBackoff = 2, 5
	separator              = string(filepath.Separator)
)

// Interface guards
var (
	_ caddy.Provisioner           = (*FileServer)(nil)
	_ caddyhttp.MiddlewareHandler = (*FileServer)(nil)
)
