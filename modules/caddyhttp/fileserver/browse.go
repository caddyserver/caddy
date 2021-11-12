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
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path"
	"strings"
	"sync"
	"text/template"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/templates"
	"go.uber.org/zap"
)

// Browse configures directory browsing.
type Browse struct {
	// Use this template file instead of the default browse template.
	TemplateFile string `json:"template_file,omitempty"`
}

func (fsrv *FileServer) serveBrowse(root, dirPath string, w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	fsrv.logger.Debug("browse enabled; listing directory contents",
		zap.String("path", dirPath),
		zap.String("root", root))

	// Navigation on the client-side gets messed up if the
	// URL doesn't end in a trailing slash because hrefs to
	// "b/c" at path "/a" end up going to "/b/c" instead
	// of "/a/b/c" - so we have to redirect in this case
	// so that the path is "/a/" and the client constructs
	// relative hrefs "b/c" to be "/a/b/c".
	//
	// Only redirect if the last element of the path (the filename) was not
	// rewritten; if the admin wanted to rewrite to the canonical path, they
	// would have, and we have to be very careful not to introduce unwanted
	// redirects and especially redirect loops! (Redirecting using the
	// original URI is necessary because that's the URI the browser knows,
	// we don't want to redirect from internally-rewritten URIs.)
	// See https://github.com/caddyserver/caddy/issues/4205.
	origReq := r.Context().Value(caddyhttp.OriginalRequestCtxKey).(http.Request)
	if path.Base(origReq.URL.Path) == path.Base(r.URL.Path) {
		if !strings.HasSuffix(origReq.URL.Path, "/") {
			fsrv.logger.Debug("redirecting to trailing slash to preserve hrefs", zap.String("request_path", r.URL.Path))
			origReq.URL.Path += "/"
			http.Redirect(w, r, origReq.URL.String(), http.StatusMovedPermanently)
			return nil
		}
	}

	dir, err := fsrv.openFile(dirPath, w)
	if err != nil {
		return err
	}
	defer dir.Close()

	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

	// calling path.Clean here prevents weird breadcrumbs when URL paths are sketchy like /%2e%2e%2f
	listing, err := fsrv.loadDirectoryContents(dir, root, path.Clean(r.URL.Path), repl)
	switch {
	case os.IsPermission(err):
		return caddyhttp.Error(http.StatusForbidden, err)
	case os.IsNotExist(err):
		return fsrv.notFound(w, r, next)
	case err != nil:
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	fsrv.browseApplyQueryParams(w, r, &listing)

	buf := bufPool.Get().(*bytes.Buffer)
	defer bufPool.Put(buf)

	acceptHeader := strings.ToLower(strings.Join(r.Header["Accept"], ","))

	// write response as either JSON or HTML
	if strings.Contains(acceptHeader, "application/json") {
		if err := json.NewEncoder(buf).Encode(listing.Items); err != nil {
			return caddyhttp.Error(http.StatusInternalServerError, err)
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
	} else {
		var fs http.FileSystem
		if fsrv.Root != "" {
			fs = http.Dir(repl.ReplaceAll(fsrv.Root, "."))
		}

		var tplCtx = &templateContext{
			TemplateContext: templates.TemplateContext{
				Root:       fs,
				Req:        r,
				RespHeader: templates.WrappedHeader{Header: w.Header()},
			},
			browseTemplateContext: listing,
		}

		tpl, err := fsrv.makeBrowseTemplate(tplCtx)
		if err != nil {
			return fmt.Errorf("parsing browse template: %v", err)
		}
		if err := tpl.Execute(buf, tplCtx); err != nil {
			return caddyhttp.Error(http.StatusInternalServerError, err)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	}

	_, _ = buf.WriteTo(w)

	return nil
}

func (fsrv *FileServer) loadDirectoryContents(dir *os.File, root, urlPath string, repl *caddy.Replacer) (browseTemplateContext, error) {
	files, err := dir.Readdir(-1)
	if err != nil {
		return browseTemplateContext{}, err
	}

	// user can presumably browse "up" to parent folder if path is longer than "/"
	canGoUp := len(urlPath) > 1

	return fsrv.directoryListing(files, canGoUp, root, urlPath, repl), nil
}

// browseApplyQueryParams applies query parameters to the listing.
// It mutates the listing and may set cookies.
func (fsrv *FileServer) browseApplyQueryParams(w http.ResponseWriter, r *http.Request, listing *browseTemplateContext) {
	sortParam := r.URL.Query().Get("sort")
	orderParam := r.URL.Query().Get("order")
	limitParam := r.URL.Query().Get("limit")
	offsetParam := r.URL.Query().Get("offset")

	// first figure out what to sort by
	switch sortParam {
	case "":
		sortParam = sortByNameDirFirst
		if sortCookie, sortErr := r.Cookie("sort"); sortErr == nil {
			sortParam = sortCookie.Value
		}
	case sortByName, sortByNameDirFirst, sortBySize, sortByTime:
		http.SetCookie(w, &http.Cookie{Name: "sort", Value: sortParam, Secure: r.TLS != nil})
	}

	// then figure out the order
	switch orderParam {
	case "":
		orderParam = "asc"
		if orderCookie, orderErr := r.Cookie("order"); orderErr == nil {
			orderParam = orderCookie.Value
		}
	case "asc", "desc":
		http.SetCookie(w, &http.Cookie{Name: "order", Value: orderParam, Secure: r.TLS != nil})
	}

	// finally, apply the sorting and limiting
	listing.applySortAndLimit(sortParam, orderParam, limitParam, offsetParam)
}

// makeBrowseTemplate creates the template to be used for directory listings.
func (fsrv *FileServer) makeBrowseTemplate(tplCtx *templateContext) (*template.Template, error) {
	var tpl *template.Template
	var err error

	if fsrv.Browse.TemplateFile != "" {
		tpl = tplCtx.NewTemplate(path.Base(fsrv.Browse.TemplateFile))
		tpl, err = tpl.ParseFiles(fsrv.Browse.TemplateFile)
		if err != nil {
			return nil, fmt.Errorf("parsing browse template file: %v", err)
		}
	} else {
		tpl = tplCtx.NewTemplate("default_listing")
		tpl, err = tpl.Parse(defaultBrowseTemplate)
		if err != nil {
			return nil, fmt.Errorf("parsing default browse template: %v", err)
		}
	}

	return tpl, nil
}

// isSymlink return true if f is a symbolic link
func isSymlink(f os.FileInfo) bool {
	return f.Mode()&os.ModeSymlink != 0
}

// isSymlinkTargetDir returns true if f's symbolic link target
// is a directory.
func isSymlinkTargetDir(f os.FileInfo, root, urlPath string) bool {
	if !isSymlink(f) {
		return false
	}
	target := caddyhttp.SanitizedPathJoin(root, path.Join(urlPath, f.Name()))
	targetInfo, err := os.Stat(target)
	if err != nil {
		return false
	}
	return targetInfo.IsDir()
}

// templateContext powers the context used when evaluating the browse template.
// It combines browse-specific features with the standard templates handler
// features.
type templateContext struct {
	templates.TemplateContext
	browseTemplateContext
}

// bufPool is used to increase the efficiency of file listings.
var bufPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}
