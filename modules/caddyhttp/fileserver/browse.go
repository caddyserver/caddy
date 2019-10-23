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
	"html/template"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/mholt/archiver/v3"
)

// Browse configures directory browsing.
type Browse struct {
	// Use this template file instead of the default browse template.
	TemplateFile string   `json:"template_file,omitempty"`
	DirArchives  []string `json:"dir_archives,omitempty"`

	template *template.Template
}

const (
	zipContentType     = "application/zip"
	zipExtension       = "zip"
	tarContentType     = "application/tar"
	tarExtension       = "tar"
	tarGzipContentType = "application/tar+gzip"
	tarGzipExtension   = "tar.gz"
)

var (
	extensionToContentType = map[string]string{zipExtension: zipContentType, tarExtension: tarContentType, tarGzipExtension: tarGzipContentType}
)

func (fsrv *FileServer) serveBrowse(dirPath string, w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// navigation on the client-side gets messed up if the
	// URL doesn't end in a trailing slash because hrefs like
	// "/b/c" on a path like "/a" end up going to "/b/c" instead
	// of "/a/b/c" - so we have to redirect in this case
	if !strings.HasSuffix(r.URL.Path, "/") {
		r.URL.Path += "/"
		http.Redirect(w, r, r.URL.String(), http.StatusMovedPermanently)
		return nil
	}

	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	suffix := repl.ReplaceAll(r.URL.Path, "")
	contentType := r.URL.Query().Get("archive")

	if contentType != "" {
		return fsrv.streamFolderAsArchive(suffix, dirPath, contentType, w, r, next)
	}

	dir, err := fsrv.openFile(dirPath, w)
	if err != nil {
		return err
	}
	defer dir.Close()

	// calling path.Clean here prevents weird breadcrumbs when URL paths are sketchy like /%2e%2e%2f
	listing, err := fsrv.loadDirectoryContents(dir, path.Clean(r.URL.Path), repl)
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
		if buf, err = fsrv.browseWriteHTML(listing); err != nil {
			return caddyhttp.Error(http.StatusInternalServerError, err)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	}

	buf.WriteTo(w)

	return nil
}

func (fsrv *FileServer) loadDirectoryContents(dir *os.File, urlPath string, repl *caddy.Replacer) (browseListing, error) {
	files, err := dir.Readdir(-1)
	if err != nil {
		return browseListing{}, err
	}

	// determine if user can browse up another folder
	curPathDir := path.Dir(strings.TrimSuffix(urlPath, "/"))
	canGoUp := strings.HasPrefix(curPathDir, fsrv.Root)

	return fsrv.directoryListing(files, canGoUp, urlPath, repl), nil
}

// browseApplyQueryParams applies query parameters to the listing.
// It mutates the listing and may set cookies.
func (fsrv *FileServer) browseApplyQueryParams(w http.ResponseWriter, r *http.Request, listing *browseListing) {
	sortParam := r.URL.Query().Get("sort")
	orderParam := r.URL.Query().Get("order")
	limitParam := r.URL.Query().Get("limit")

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
	listing.applySortAndLimit(sortParam, orderParam, limitParam)
}

func (fsrv *FileServer) browseWriteJSON(listing browseListing) (*bytes.Buffer, error) {
	buf := bufPool.Get().(*bytes.Buffer)
	err := json.NewEncoder(buf).Encode(listing.Items)
	bufPool.Put(buf)
	return buf, err
}

func (fsrv *FileServer) browseWriteHTML(listing browseListing) (*bytes.Buffer, error) {
	buf := bufPool.Get().(*bytes.Buffer)
	err := fsrv.Browse.template.Execute(buf, listing)
	bufPool.Put(buf)
	return buf, err
}

func (fsrv *FileServer) streamFolderAsArchive(baseFolderName, downloadFolderName, extension string, w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	baseFolderName = baseFolderName[1:] // Remove initial slash
	if err := validateExtension(extension); err != nil {
		return writeUnsupportedMediaType(w, err)
	}
	contentType := extensionToContentType[extension]

	writer, err := fsrv.getArchiveWriter(contentType)
	if err != nil {
		return writeUnsupportedMediaType(w, err)
	}
	defer writer.Close()

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s.%s\"", path.Base(baseFolderName), extension))
	err = writer.Create(w)
	if err != nil {
		return err
	}

	downloadFolderInfo, err := os.Stat(downloadFolderName)
	if err != nil {
		if os.IsNotExist(err) {
			return fsrv.notFound(w, r, next)
		}
		return err
	}

	err = filepath.Walk(downloadFolderName, func(fpath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info == nil {
			return fmt.Errorf("nil file info")
		}

		// open the file, if it has any content
		var file io.ReadCloser
		if info.Mode().IsRegular() {
			file, err = os.Open(fpath)
			if err != nil {
				return fmt.Errorf("%s: opening: %v", fpath, err)
			}
			defer file.Close()
		}

		// make its archive-internal name
		internalName, err := archiver.NameInArchive(downloadFolderInfo, downloadFolderName, fpath)
		if err != nil {
			return fmt.Errorf("making internal archive name for %s: %v", fpath, err)
		}

		// write the file to the archive
		err = writer.Write(archiver.File{
			FileInfo: archiver.FileInfo{
				FileInfo:   info,
				CustomName: internalName,
			},
			ReadCloser: file,
		})
		if err != nil {
			return fmt.Errorf("writing file to archive: %v", err)
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("walking %s: %v", downloadFolderName, err)
	}

	return nil
}

func (fsrv *FileServer) getArchiveWriter(contentType string) (archiver.Writer, error) {
	switch contentType {
	default:
		return nil, fmt.Errorf("A file format with content type %v is not supported", contentType)
	case zipContentType:
		return &archiver.Zip{
			CompressionLevel:       0,
			MkdirAll:               true,
			SelectiveCompression:   true,
			ImplicitTopLevelFolder: true,
		}, nil
	case tarContentType:
		return &archiver.Tar{MkdirAll: true, ImplicitTopLevelFolder: true}, nil
	case tarGzipContentType:
		return &archiver.TarGz{Tar: &archiver.Tar{MkdirAll: true, ImplicitTopLevelFolder: true}}, nil
	}
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

func validateArchiveSelection(extensions []string) error {
	var invalidExtensions []string

	for _, extension := range extensions {
		if _, keyFound := extensionToContentType[extension]; !keyFound {
			invalidExtensions = append(invalidExtensions, extension)
		}
	}

	if len(invalidExtensions) == 0 {
		return nil
	}

	return fmt.Errorf("these extensions are not valid choices %v", invalidExtensions)
}

func validateExtension(extension string) error {
	if _, ok := extensionToContentType[extension]; !ok {
		return fmt.Errorf("A file format with extension %v is not supported", extension)
	}
	return nil
}

func writeUnsupportedMediaType(w http.ResponseWriter, err error) error {
	w.WriteHeader(415)
	_, err = w.Write([]byte(fmt.Sprint(err)))
	return err
}
