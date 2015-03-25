package server

import (
	"net/http"
	"path"
	"strings"

	"github.com/mholt/caddy/middleware/browse"
)

// This FileServer is adapted from the one in net/http
// by the Go authors. Some modifications have been made.
//
// License:
//
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
func FileServer(root http.FileSystem) http.Handler {
	return &fileHandler{root}
}

type fileHandler struct {
	root http.FileSystem
}

func (f *fileHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	upath := r.URL.Path
	if !strings.HasPrefix(upath, "/") {
		upath = "/" + upath
		r.URL.Path = upath
	}
	serveFile(w, r, f.root, path.Clean(upath), true)
}

// name is '/'-separated, not filepath.Separator.
func serveFile(w http.ResponseWriter, r *http.Request, fs http.FileSystem, name string, redirect bool) {
	f, err := fs.Open(name)
	if err != nil {
		// TODO expose actual error?
		http.NotFound(w, r)
		return
	}
	defer f.Close()

	d, err1 := f.Stat()
	if err1 != nil {
		// TODO expose actual error?
		http.NotFound(w, r)
		return
	}

	// use contents of an index file, if present, for directory
	if d.IsDir() {
		for _, indexPage := range browse.IndexPages {
			index := strings.TrimSuffix(name, "/") + "/" + indexPage
			ff, err := fs.Open(index)
			if err == nil {
				defer ff.Close()
				dd, err := ff.Stat()
				if err == nil {
					name = index
					d = dd
					f = ff
					break
				}
			}
		}
	}

	// Still a directory? (we didn't find an index file)
	if d.IsDir() {
		http.NotFound(w, r) // 404 instead of 403 to hide the fact that the folder exists
		return
	}

	http.ServeContent(w, r, d.Name(), d.ModTime(), f)
}
