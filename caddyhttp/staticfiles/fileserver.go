// Copyright 2015 Light Code Labs, LLC
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

// Package staticfiles provides middleware for serving static files from disk.
// Its handler is the default HTTP handler for the HTTP server.
//
// TODO: Should this package be rolled into the httpserver package?
package staticfiles

import (
	"math/rand"
	"net/http"
	"os"
	"path"
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
	Root http.FileSystem // jailed access to the file system
	Hide []string        // list of files for which to respond with "Not Found"

	// A list of pages that may be understood as the "index" files to directories.
	// Injected from *SiteConfig.
	IndexPages []string
}

// ServeHTTP serves static files for r according to fs's configuration.
func (fs FileServer) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	return fs.serveFile(w, r)
}

// serveFile writes the specified file to the HTTP response.
// name is '/'-separated, not filepath.Separator.
func (fs FileServer) serveFile(w http.ResponseWriter, r *http.Request) (int, error) {
	reqPath := r.URL.Path

	// Prevent absolute path access on Windows.
	// TODO remove when stdlib http.Dir fixes this.
	if runtime.GOOS == "windows" && len(reqPath) > 0 && filepath.IsAbs(reqPath[1:]) {
		return http.StatusNotFound, nil
	}

	// open the requested file
	f, err := fs.Root.Open(reqPath)
	if err != nil {
		if os.IsNotExist(err) {
			return http.StatusNotFound, nil
		} else if os.IsPermission(err) {
			return http.StatusForbidden, err
		}
		// otherwise, maybe the server is under load and ran out of file descriptors?
		backoff := int(3 + rand.Int31()%3) // 3–5 seconds to prevent a stampede
		w.Header().Set("Retry-After", strconv.Itoa(backoff))
		return http.StatusServiceUnavailable, err
	}
	defer f.Close()

	// get information about the file
	d, err := f.Stat()
	if err != nil {
		if os.IsNotExist(err) {
			return http.StatusNotFound, nil
		} else if os.IsPermission(err) {
			return http.StatusForbidden, err
		}
		// return a different status code than above to distinguish these cases
		return http.StatusInternalServerError, err
	}

	// redirect to canonical path (being careful to preserve other parts of URL and
	// considering cases where a site is defined with a path prefix that gets stripped)
	urlCopy := *r.URL
	pathPrefix, _ := r.Context().Value(caddy.CtxKey("path_prefix")).(string)
	if pathPrefix != "/" {
		urlCopy.Path = pathPrefix + urlCopy.Path
	}
	if urlCopy.Path == "" {
		urlCopy.Path = "/"
	}
	if d.IsDir() {
		// ensure there is a trailing slash
		if urlCopy.Path[len(urlCopy.Path)-1] != '/' {
			for strings.HasPrefix(urlCopy.Path, "//") {
				// prevent path-based open redirects
				urlCopy.Path = strings.TrimPrefix(urlCopy.Path, "/")
			}
			urlCopy.Path += "/"
			http.Redirect(w, r, urlCopy.String(), http.StatusMovedPermanently)
			return http.StatusMovedPermanently, nil
		}
	} else {
		// ensure no trailing slash
		redir := false
		if urlCopy.Path[len(urlCopy.Path)-1] == '/' {
			urlCopy.Path = urlCopy.Path[:len(urlCopy.Path)-1]
			redir = true
		}

		// if an index file was explicitly requested, strip file name from the request
		// ("/foo/index.html" -> "/foo/")
		var requestPage = path.Base(urlCopy.Path)
		for _, indexPage := range fs.IndexPages {
			if requestPage == indexPage {
				urlCopy.Path = urlCopy.Path[:len(urlCopy.Path)-len(indexPage)]
				redir = true
				break
			}
		}

		if redir {
			for strings.HasPrefix(urlCopy.Path, "//") {
				// prevent path-based open redirects
				urlCopy.Path = strings.TrimPrefix(urlCopy.Path, "/")
			}
			http.Redirect(w, r, urlCopy.String(), http.StatusMovedPermanently)
			return http.StatusMovedPermanently, nil
		}
	}

	// use contents of an index file, if present, for directory requests
	if d.IsDir() {
		for _, indexPage := range fs.IndexPages {
			indexPath := path.Join(reqPath, indexPage)
			indexFile, err := fs.Root.Open(indexPath)
			if err != nil {
				continue
			}

			indexInfo, err := indexFile.Stat()
			if err != nil {
				indexFile.Close()
				continue
			}

			// this defer does not leak fds even though we are in a loop,
			// because previous iterations of the loop must have had an
			// err, so there's nothing to close from earlier iterations.
			defer indexFile.Close()

			// close previously-opened file immediately to release fd
			f.Close()

			// switch to using the index file, and we're done here
			d = indexInfo
			f = indexFile
			reqPath = indexPath
			break
		}
	}

	// return Not Found if we either did not find an index file (and thus are
	// still a directory) or if this file is supposed to be hidden
	if d.IsDir() || fs.IsHidden(d) {
		return http.StatusNotFound, nil
	}

	etag := calculateEtag(d)

	// look for compressed versions of the file on disk, if the client supports that encoding
	for _, encoding := range staticEncodingPriority {
		// see if the client accepts a compressed encoding we offer
		acceptEncoding := strings.Split(r.Header.Get("Accept-Encoding"), ",")
		accepted := false
		for _, acc := range acceptEncoding {
			if strings.TrimSpace(acc) == encoding {
				accepted = true
				break
			}
		}

		// if client doesn't support this encoding, don't even bother; try next one
		if !accepted {
			continue
		}

		// see if the compressed version of this file exists
		encodedFile, err := fs.Root.Open(reqPath + staticEncoding[encoding])
		if err != nil {
			continue
		}

		encodedFileInfo, err := encodedFile.Stat()
		if err != nil {
			encodedFile.Close()
			continue
		}

		// close the encoded file when we're done, and close the
		// previously-opened file immediately to release the fd
		defer encodedFile.Close()
		f.Close()

		// the encoded file is now what we're serving
		f = encodedFile
		etag = calculateEtag(encodedFileInfo)
		w.Header().Add("Vary", "Accept-Encoding")
		w.Header().Set("Content-Encoding", encoding)
		w.Header().Set("Content-Length", strconv.FormatInt(encodedFileInfo.Size(), 10))
		break
	}

	// Set the ETag returned to the user-agent. Note that a conditional If-None-Match
	// request is handled in http.ServeContent below, which checks against this ETag value.
	w.Header().Set("ETag", etag)

	// Note: Errors generated by ServeContent are written immediately
	// to the response. This usually only happens if seeking fails (rare).
	// Its signature does not bubble the error up to us, so we cannot
	// return it for any logging middleware to record. Oh well.
	http.ServeContent(w, r, d.Name(), d.ModTime(), f)

	return http.StatusOK, nil
}

// IsHidden checks if file with FileInfo d is on hide list.
func (fs FileServer) IsHidden(d os.FileInfo) bool {
	for _, hiddenPath := range fs.Hide {
		// TODO: Could these FileInfos be stored instead of their paths, to avoid opening them all the time?
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

// DefaultIndexPages is a list of pages that may be understood as
// the "index" files to directories.
var DefaultIndexPages = []string{
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
