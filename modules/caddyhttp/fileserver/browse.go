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

	template *template.Template
}

func (fsrv *FileServer) serveBrowse(root, dirPath string, w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	fsrv.logger.Debug("browse enabled; listing directory contents",
		zap.String("path", dirPath),
		zap.String("root", root))

	// navigation on the client-side gets messed up if the
	// URL doesn't end in a trailing slash because hrefs like
	// "/b/c" on a path like "/a" end up going to "/b/c" instead
	// of "/a/b/c" - so we have to redirect in this case
	if !strings.HasSuffix(r.URL.Path, "/") {
		fsrv.logger.Debug("redirecting to trailing slash to preserve hrefs", zap.String("request_path", r.URL.Path))
		r.URL.Path += "/"
		http.Redirect(w, r, r.URL.String(), http.StatusMovedPermanently)
		return nil
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

	// write response as either JSON or HTML
	var buf *bytes.Buffer
	acceptHeader := strings.ToLower(strings.Join(r.Header["Accept"], ","))
	if strings.Contains(acceptHeader, "application/json") {
		if buf, err = fsrv.browseWriteJSON(listing); err != nil {
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

		err = fsrv.makeBrowseTemplate(tplCtx)
		if err != nil {
			return fmt.Errorf("parsing browse template: %v", err)
		}

		if buf, err = fsrv.browseWriteHTML(tplCtx); err != nil {
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
func (fsrv *FileServer) makeBrowseTemplate(tplCtx *templateContext) error {
	var tpl *template.Template
	var err error

	if fsrv.Browse.TemplateFile != "" {
		tpl = tplCtx.NewTemplate(path.Base(fsrv.Browse.TemplateFile))
		tpl, err = tpl.ParseFiles(fsrv.Browse.TemplateFile)
		if err != nil {
			return fmt.Errorf("parsing browse template file: %v", err)
		}
	} else {
		tpl = tplCtx.NewTemplate("default_listing")
		tpl, err = tpl.Parse(defaultBrowseTemplate)
		if err != nil {
			return fmt.Errorf("parsing default browse template: %v", err)
		}
	}

	fsrv.Browse.template = tpl

	return nil
}

func (fsrv *FileServer) browseWriteJSON(listing browseTemplateContext) (*bytes.Buffer, error) {
	buf := bufPool.Get().(*bytes.Buffer)
	defer bufPool.Put(buf)
	err := json.NewEncoder(buf).Encode(listing.Items)
	return buf, err
}

func (fsrv *FileServer) browseWriteHTML(tplCtx *templateContext) (*bytes.Buffer, error) {
	buf := bufPool.Get().(*bytes.Buffer)
	defer bufPool.Put(buf)
	err := fsrv.Browse.template.Execute(buf, tplCtx)
	return buf, err
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
	target := sanitizedPathJoin(root, path.Join(urlPath, f.Name()))
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
