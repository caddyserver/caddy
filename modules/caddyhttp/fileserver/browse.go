package fileserver

import (
	"bytes"
	"encoding/json"
	"html/template"
	"net/http"
	"os"
	"path"
	"strings"

	"bitbucket.org/lightcodelabs/caddy2"
	"bitbucket.org/lightcodelabs/caddy2/modules/caddyhttp"
)

// Browse configures directory browsing.
type Browse struct {
	TemplateFile string `json:"template_file,omitempty"`

	template *template.Template
}

func (fsrv *FileServer) serveBrowse(dirPath string, w http.ResponseWriter, r *http.Request) error {
	// navigation on the client-side gets messed up if the
	// URL doesn't end in a trailing slash because hrefs like
	// "/b/c" on a path like "/a" end up going to "/b/c" instead
	// of "/a/b/c" - so we have to redirect in this case
	if !strings.HasSuffix(r.URL.Path, "/") {
		r.URL.Path += "/"
		http.Redirect(w, r, r.URL.String(), http.StatusMovedPermanently)
		return nil
	}

	dir, err := fsrv.openFile(dirPath, w)
	if err != nil {
		return err
	}
	defer dir.Close()

	repl := r.Context().Value(caddy2.ReplacerCtxKey).(caddy2.Replacer)

	// calling path.Clean here prevents weird breadcrumbs when URL paths are sketchy like /%2e%2e%2f
	listing, err := fsrv.loadDirectoryContents(dir, path.Clean(r.URL.Path), repl)
	switch {
	case os.IsPermission(err):
		return caddyhttp.Error(http.StatusForbidden, err)
	case os.IsNotExist(err):
		return caddyhttp.Error(http.StatusNotFound, err)
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

func (fsrv *FileServer) loadDirectoryContents(dir *os.File, urlPath string, repl caddy2.Replacer) (browseListing, error) {
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
	buf := new(bytes.Buffer)
	err := json.NewEncoder(buf).Encode(listing.Items)
	return buf, err
}

func (fsrv *FileServer) browseWriteHTML(listing browseListing) (*bytes.Buffer, error) {
	buf := new(bytes.Buffer)
	err := fsrv.Browse.template.Execute(buf, listing)
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
