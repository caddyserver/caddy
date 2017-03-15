package staticfiles

import (
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/mholt/caddy"
)

// FileServer implements a production-ready file server
// and is the 'default' handler for all requests to Caddy.
// It simply loads and serves the URI requested. FileServer
// is adapted from the one in net/http by the Go authors.
// Significant modifications have been made.
//
// Original license:
//
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
type FileServer struct {
	// Jailed disk access
	Root http.FileSystem

	// List of files to treat as "Not Found"
	Hide []string
}

// ServeHTTP serves static files for r according to fs's configuration.
func (fs FileServer) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	// r.URL.Path has already been cleaned by Caddy.
	if r.URL.Path == "" {
		r.URL.Path = "/"
	}
	return fs.serveFile(w, r, r.URL.Path)
}

// calculateEtag produces a strong etag by default. Prefix the result with "W/" to convert this into a weak one.
// see https://tools.ietf.org/html/rfc7232#section-2.3
func calculateEtag(d os.FileInfo) string {
	t := strconv.FormatInt(d.ModTime().Unix(), 36)
	s := strconv.FormatInt(d.Size(), 36)
	return `"` + t + s + `"`
}

// serveFile writes the specified file to the HTTP response.
// name is '/'-separated, not filepath.Separator.
func (fs FileServer) serveFile(w http.ResponseWriter, r *http.Request, name string) (int, error) {

	location := name

	// Prevent absolute path access on Windows.
	// TODO remove when stdlib http.Dir fixes this.
	if runtime.GOOS == "windows" {
		if filepath.IsAbs(name[1:]) {
			return http.StatusNotFound, nil
		}
	}

	f, err := fs.Root.Open(name)
	if err != nil {
		// TODO: remove when http.Dir handles this
		// Go issue #18984
		err = mapFSRootOpenErr(err)
		if os.IsNotExist(err) {
			return http.StatusNotFound, nil
		} else if os.IsPermission(err) {
			return http.StatusForbidden, err
		}
		// Likely the server is under load and ran out of file descriptors
		backoff := int(3 + rand.Int31()%3) // 3–5 seconds to prevent a stampede
		w.Header().Set("Retry-After", strconv.Itoa(backoff))
		return http.StatusServiceUnavailable, err
	}
	defer f.Close()

	d, err := f.Stat()
	if err != nil {
		if os.IsNotExist(err) {
			return http.StatusNotFound, nil
		} else if os.IsPermission(err) {
			return http.StatusForbidden, err
		}
		// Return a different status code than above so as to distinguish these cases
		return http.StatusInternalServerError, err
	}

	// redirect to canonical path
	if d.IsDir() {
		// Ensure / at end of directory url. If the original URL path is
		// used then ensure / exists as well.
		if !strings.HasSuffix(r.URL.Path, "/") {
			RedirectToDir(w, r)
			return http.StatusMovedPermanently, nil
		}
	} else {
		// Ensure no / at end of file url. If the original URL path is
		// used then ensure no / exists as well.
		if strings.HasSuffix(r.URL.Path, "/") {
			RedirectToFile(w, r)
			return http.StatusMovedPermanently, nil
		}
	}

	// use contents of an index file, if present, for directory
	if d.IsDir() {
		for _, indexPage := range IndexPages {
			index := strings.TrimSuffix(name, "/") + "/" + indexPage
			ff, err := fs.Root.Open(index)
			if err != nil {
				continue
			}

			// this defer does not leak fds because previous iterations
			// of the loop must have had an err, so nothing to close
			defer ff.Close()

			dd, err := ff.Stat()
			if err != nil {
				ff.Close()
				continue
			}

			// Close previous file - release fd immediately
			f.Close()

			d = dd
			f = ff
			location = index
			break
		}
	}

	// Still a directory? (we didn't find an index file)
	// Return 404 to hide the fact that the folder exists
	if d.IsDir() {
		return http.StatusNotFound, nil
	}

	if fs.IsHidden(d) {
		return http.StatusNotFound, nil
	}

	filename := d.Name()
	etag := calculateEtag(d) // strong

	for _, encoding := range staticEncodingPriority {
		acceptEncoding := strings.Split(r.Header.Get("Accept-Encoding"), ",")

		accepted := false
		for _, acc := range acceptEncoding {
			if accepted || strings.TrimSpace(acc) == encoding {
				accepted = true
			}
		}

		if !accepted {
			continue
		}

		encodedFile, err := fs.Root.Open(location + staticEncoding[encoding])
		if err != nil {
			continue
		}

		encodedFileInfo, err := encodedFile.Stat()
		if err != nil {
			encodedFile.Close()
			continue
		}

		// Close previous file - release fd
		f.Close()

		etag = calculateEtag(encodedFileInfo)

		// Encoded file will be served
		f = encodedFile

		w.Header().Add("Vary", "Accept-Encoding")
		w.Header().Set("Content-Encoding", encoding)
		w.Header().Set("Content-Length", strconv.FormatInt(encodedFileInfo.Size(), 10))

		defer f.Close()
		break
	}

	// Set the ETag returned to the user-agent. Note that a conditional If-None-Match
	// request is handled in http.ServeContent below, which checks against this ETag value.
	w.Header().Set("ETag", etag)

	// Note: Errors generated by ServeContent are written immediately
	// to the response. This usually only happens if seeking fails (rare).
	http.ServeContent(w, r, filename, d.ModTime(), f)

	return http.StatusOK, nil
}

// IsHidden checks if file with FileInfo d is on hide list.
func (fs FileServer) IsHidden(d os.FileInfo) bool {
	// If the file is supposed to be hidden, return a 404
	for _, hiddenPath := range fs.Hide {
		// Check if the served file is exactly the hidden file.
		if hFile, err := fs.Root.Open(hiddenPath); err == nil {
			fs, _ := hFile.Stat()
			hFile.Close()
			if os.SameFile(d, fs) {
				return true
			}
		}
	}
	return false
}

// RedirectToDir replies to the request with a redirect to the URL in r, which
// has been transformed to indicate that the resource being requested is a
// directory.
func RedirectToDir(w http.ResponseWriter, r *http.Request) {
	toURL, _ := url.Parse(r.URL.String())

	path, ok := r.Context().Value(URLPathCtxKey).(string)
	if ok && !strings.HasSuffix(path, "/") {
		toURL.Path = path
	}
	toURL.Path += "/"

	http.Redirect(w, r, toURL.String(), http.StatusMovedPermanently)
}

// RedirectToFile replies to the request with a redirect to the URL in r, which
// has been transformed to indicate that the resource being requested is a
// file.
func RedirectToFile(w http.ResponseWriter, r *http.Request) {
	toURL, _ := url.Parse(r.URL.String())

	path, ok := r.Context().Value(URLPathCtxKey).(string)
	if ok && strings.HasSuffix(path, "/") {
		toURL.Path = path
	}
	toURL.Path = strings.TrimSuffix(toURL.Path, "/")

	http.Redirect(w, r, toURL.String(), http.StatusMovedPermanently)
}

// IndexPages is a list of pages that may be understood as
// the "index" files to directories.
var IndexPages = []string{
	"index.html",
	"index.htm",
	"index.txt",
	"default.html",
	"default.htm",
	"default.txt",
}

// staticEncoding is a map of content-encoding to a file extension.
// If client accepts given encoding (via Accept-Encoding header) and compressed file with given extensions exists
// it will be served to the client instead of original one.
var staticEncoding = map[string]string{
	"gzip": ".gz",
	"br":   ".br",
}

// staticEncodingPriority is a list of preferred static encodings (most efficient compression to least one).
var staticEncodingPriority = []string{
	"br",
	"gzip",
}

// mapFSRootOpenErr maps the provided non-nil error
// to a possibly better non-nil error. In particular, it turns OS-specific errors
// about opening files in non-directories into os.ErrNotExist.
//
// TODO: remove when http.Dir handles this
// Go issue #18984
func mapFSRootOpenErr(originalErr error) error {
	if os.IsNotExist(originalErr) || os.IsPermission(originalErr) {
		return originalErr
	}

	perr, ok := originalErr.(*os.PathError)
	if !ok {
		return originalErr
	}
	name := perr.Path
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

// URLPathCtxKey is a context key. It can be used in HTTP handlers with
// context.WithValue to access the original request URI that accompanied the
// server request. The associated value will be of type string.
const URLPathCtxKey caddy.CtxKey = "url_path"
