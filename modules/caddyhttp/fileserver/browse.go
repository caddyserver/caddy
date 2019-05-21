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
	TemplateFile string `json:"template_file"`

	template *template.Template
}

func (fsrv *FileServer) serveBrowse(dirPath string, w http.ResponseWriter, r *http.Request) error {
	dir, err := fsrv.openFile(dirPath, w)
	if err != nil {
		return err
	}
	defer dir.Close()

	repl := r.Context().Value(caddy2.ReplacerCtxKey).(caddy2.Replacer)

	listing, err := fsrv.loadDirectoryContents(dir, r.URL.Path, repl)
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

	// TODO: Sigh... do we have to put this here?
	// // Browsing navigation gets messed up if browsing a directory
	// // that doesn't end in "/" (which it should, anyway)
	// u := *r.URL
	// if u.Path == "" {
	// 	u.Path = "/"
	// }
	// if u.Path[len(u.Path)-1] != '/' {
	// 	u.Path += "/"
	// 	http.Redirect(w, r, u.String(), http.StatusMovedPermanently)
	// 	return http.StatusMovedPermanently, nil
	// }

	// return b.ServeListing(w, r, requestedFilepath, bc)
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

// isSymlinkTargetDir return true if f's symbolic link target
// is a directory. Return false if not a symbolic link.
// TODO: Re-implement
func isSymlinkTargetDir(f os.FileInfo, urlPath string) bool {
	// if !isSymlink(f) {
	// 	return false
	// }

	// // TODO: Ensure path is sanitized
	// target:= path.Join(root, urlPath, f.Name()))
	// targetInfo, err := os.Stat(target)
	// if err != nil {
	// 	return false
	// }
	// return targetInfo.IsDir()
	return false
}
