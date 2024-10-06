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
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"strings"
	"sync"
	"text/tabwriter"
	"text/template"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/templates"
)

// BrowseTemplate is the default template document to use for
// file listings. By default, its default value is an embedded
// document. You can override this value at program start, or
// if you are running Caddy via config, you can specify a
// custom template_file in the browse configuration.
//
//go:embed browse.html
var BrowseTemplate string

// Browse configures directory browsing.
type Browse struct {
	// Filename of the template to use instead of the embedded browse template.
	TemplateFile string `json:"template_file,omitempty"`

	// Determines whether or not targets of symlinks should be revealed.
	RevealSymlinks bool `json:"reveal_symlinks,omitempty"`

	// Override the default sort.
	// It includes the following options:
	//   - sort_by: name(default), namedirfirst, size, time
	//   - order: asc(default), desc
	// eg.:
	//   - `sort time desc` will sort by time in descending order
	//   - `sort size` will sort by size in ascending order
	// The first option must be `sort_by` and the second option must be `order` (if exists).
	SortOptions []string `json:"sort,omitempty"`

	// FileLimit limits the number of up to n DirEntry values in directory order.
	FileLimit int `json:"file_limit,omitempty"`
}

const (
	defaultDirEntryLimit = 10000
)

func (fsrv *FileServer) serveBrowse(fileSystem fs.FS, root, dirPath string, w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if c := fsrv.logger.Check(zapcore.DebugLevel, "browse enabled; listing directory contents"); c != nil {
		c.Write(zap.String("path", dirPath), zap.String("root", root))
	}

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
	// We also redirect if the path is empty, because this implies the path
	// prefix was fully stripped away by a `handle_path` handler for example.
	// See https://github.com/caddyserver/caddy/issues/4466.
	origReq := r.Context().Value(caddyhttp.OriginalRequestCtxKey).(http.Request)
	if r.URL.Path == "" || path.Base(origReq.URL.Path) == path.Base(r.URL.Path) {
		if !strings.HasSuffix(origReq.URL.Path, "/") {
			if c := fsrv.logger.Check(zapcore.DebugLevel, "redirecting to trailing slash to preserve hrefs"); c != nil {
				c.Write(zap.String("request_path", r.URL.Path))
			}
			return redirect(w, r, origReq.URL.Path+"/")
		}
	}

	dir, err := fsrv.openFile(fileSystem, dirPath, w)
	if err != nil {
		return err
	}
	defer dir.Close()

	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

	// TODO: not entirely sure if path.Clean() is necessary here but seems like a safe plan (i.e. /%2e%2e%2f) - someone could verify this
	listing, err := fsrv.loadDirectoryContents(r.Context(), fileSystem, dir.(fs.ReadDirFile), root, path.Clean(r.URL.EscapedPath()), repl)
	switch {
	case errors.Is(err, fs.ErrPermission):
		return caddyhttp.Error(http.StatusForbidden, err)
	case errors.Is(err, fs.ErrNotExist):
		return fsrv.notFound(w, r, next)
	case err != nil:
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	w.Header().Add("Vary", "Accept, Accept-Encoding")

	// speed up browser/client experience and caching by supporting If-Modified-Since
	if ifModSinceStr := r.Header.Get("If-Modified-Since"); ifModSinceStr != "" {
		// basically a copy of stdlib file server's handling of If-Modified-Since
		ifModSince, err := http.ParseTime(ifModSinceStr)
		if err == nil && listing.lastModified.Truncate(time.Second).Compare(ifModSince) <= 0 {
			w.WriteHeader(http.StatusNotModified)
			return nil
		}
	}

	fsrv.browseApplyQueryParams(w, r, listing)

	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufPool.Put(buf)

	acceptHeader := strings.ToLower(strings.Join(r.Header["Accept"], ","))
	w.Header().Set("Last-Modified", listing.lastModified.Format(http.TimeFormat))

	switch {
	case strings.Contains(acceptHeader, "application/json"):
		if err := json.NewEncoder(buf).Encode(listing.Items); err != nil {
			return caddyhttp.Error(http.StatusInternalServerError, err)
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")

	case strings.Contains(acceptHeader, "text/plain"):
		writer := tabwriter.NewWriter(buf, 0, 8, 1, '\t', tabwriter.AlignRight)

		// Header on top
		if _, err := fmt.Fprintln(writer, "Name\tSize\tModified"); err != nil {
			return caddyhttp.Error(http.StatusInternalServerError, err)
		}

		// Lines to separate the header
		if _, err := fmt.Fprintln(writer, "----\t----\t--------"); err != nil {
			return caddyhttp.Error(http.StatusInternalServerError, err)
		}

		// Actual files
		for _, item := range listing.Items {
			if _, err := fmt.Fprintf(writer, "%s\t%s\t%s\n",
				item.Name, item.HumanSize(), item.HumanModTime("January 2, 2006 at 15:04:05"),
			); err != nil {
				return caddyhttp.Error(http.StatusInternalServerError, err)
			}
		}

		if err := writer.Flush(); err != nil {
			return caddyhttp.Error(http.StatusInternalServerError, err)
		}

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")

	default:
		var fs http.FileSystem
		if fsrv.Root != "" {
			fs = http.Dir(repl.ReplaceAll(fsrv.Root, "."))
		}

		tplCtx := &templateContext{
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

func (fsrv *FileServer) loadDirectoryContents(ctx context.Context, fileSystem fs.FS, dir fs.ReadDirFile, root, urlPath string, repl *caddy.Replacer) (*browseTemplateContext, error) {
	// modTime for the directory itself
	stat, err := dir.Stat()
	if err != nil {
		return nil, err
	}
	dirLimit := defaultDirEntryLimit
	if fsrv.Browse.FileLimit != 0 {
		dirLimit = fsrv.Browse.FileLimit
	}
	files, err := dir.ReadDir(dirLimit)
	if err != nil && err != io.EOF {
		return nil, err
	}

	// user can presumably browse "up" to parent folder if path is longer than "/"
	canGoUp := len(urlPath) > 1

	return fsrv.directoryListing(ctx, fileSystem, stat.ModTime(), files, canGoUp, root, urlPath, repl), nil
}

// browseApplyQueryParams applies query parameters to the listing.
// It mutates the listing and may set cookies.
func (fsrv *FileServer) browseApplyQueryParams(w http.ResponseWriter, r *http.Request, listing *browseTemplateContext) {
	var orderParam, sortParam string

	// The configs in Caddyfile have lower priority than Query params,
	// so put it at first.
	for idx, item := range fsrv.Browse.SortOptions {
		// Only `sort` & `order`, 2 params are allowed
		if idx >= 2 {
			break
		}
		switch item {
		case sortByName, sortByNameDirFirst, sortBySize, sortByTime:
			sortParam = item
		case sortOrderAsc, sortOrderDesc:
			orderParam = item
		}
	}

	layoutParam := r.URL.Query().Get("layout")
	limitParam := r.URL.Query().Get("limit")
	offsetParam := r.URL.Query().Get("offset")
	sortParamTmp := r.URL.Query().Get("sort")
	if sortParamTmp != "" {
		sortParam = sortParamTmp
	}
	orderParamTmp := r.URL.Query().Get("order")
	if orderParamTmp != "" {
		orderParam = orderParamTmp
	}

	switch layoutParam {
	case "list", "grid", "":
		listing.Layout = layoutParam
	default:
		listing.Layout = "list"
	}

	// figure out what to sort by
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
		orderParam = sortOrderAsc
		if orderCookie, orderErr := r.Cookie("order"); orderErr == nil {
			orderParam = orderCookie.Value
		}
	case sortOrderAsc, sortOrderDesc:
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
		tpl, err = tpl.Parse(BrowseTemplate)
		if err != nil {
			return nil, fmt.Errorf("parsing default browse template: %v", err)
		}
	}

	return tpl, nil
}

// isSymlinkTargetDir returns true if f's symbolic link target
// is a directory.
func (fsrv *FileServer) isSymlinkTargetDir(fileSystem fs.FS, f fs.FileInfo, root, urlPath string) bool {
	if !isSymlink(f) {
		return false
	}
	target := caddyhttp.SanitizedPathJoin(root, path.Join(urlPath, f.Name()))
	targetInfo, err := fs.Stat(fileSystem, target)
	if err != nil {
		return false
	}
	return targetInfo.IsDir()
}

// isSymlink return true if f is a symbolic link.
func isSymlink(f fs.FileInfo) bool {
	return f.Mode()&os.ModeSymlink != 0
}

// templateContext powers the context used when evaluating the browse template.
// It combines browse-specific features with the standard templates handler
// features.
type templateContext struct {
	templates.TemplateContext
	*browseTemplateContext
}

// bufPool is used to increase the efficiency of file listings.
var bufPool = sync.Pool{
	New: func() any {
		return new(bytes.Buffer)
	},
}
