// Package browse provides middleware for listing files in a directory
// when directory path is requested instead of a specific file.
package browse

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/mholt/caddy/middleware"
)

// Browse is an http.Handler that can show a file listing when
// directories in the given paths are specified.
type Browse struct {
	Next          middleware.Handler
	Root          string
	Configs       []Config
	IgnoreIndexes bool
}

// Config is a configuration for browsing in a particular path.
type Config struct {
	PathScope string
	Variables interface{}
	Template  *template.Template
}

// A Listing is the context used to fill out a template.
type Listing struct {
	// The name of the directory (the last element of the path)
	Name string

	// The full path of the request
	Path string

	// Whether the parent directory is browsable
	CanGoUp bool

	// The items (files and folders) in the path
	Items []FileInfo

	// The number of directories in the listing
	NumDirs int

	// The number of files (items that aren't directories) in the listing
	NumFiles int

	// Which sorting order is used
	Sort string

	// And which order
	Order string

	// Optional custom variables for use in browse templates
	User interface{}

	middleware.Context
}

// BreadcrumbMap returns l.Path where every element is a map
// of URLs and path segment names.
func (l Listing) BreadcrumbMap() map[string]string {
	result := map[string]string{}

	if len(l.Path) == 0 {
		return result
	}

	// skip trailing slash
	lpath := l.Path
	if lpath[len(lpath)-1] == '/' {
		lpath = lpath[:len(lpath)-1]
	}

	parts := strings.Split(lpath, "/")
	for i, part := range parts {
		if i == 0 && part == "" {
			// Leading slash (root)
			result["/"] = "/"
			continue
		}
		result[strings.Join(parts[:i+1], "/")] = part
	}

	return result
}

// FileInfo is the info about a particular file or directory
type FileInfo struct {
	IsDir   bool
	Name    string
	Size    int64
	URL     string
	ModTime time.Time
	Mode    os.FileMode
}

// HumanSize returns the size of the file as a human-readable string
// in IEC format (i.e. power of 2 or base 1024).
func (fi FileInfo) HumanSize() string {
	return humanize.IBytes(uint64(fi.Size))
}

// HumanModTime returns the modified time of the file as a human-readable string.
func (fi FileInfo) HumanModTime(format string) string {
	return fi.ModTime.Format(format)
}

// Implement sorting for Listing
type byName Listing
type bySize Listing
type byTime Listing

// By Name
func (l byName) Len() int      { return len(l.Items) }
func (l byName) Swap(i, j int) { l.Items[i], l.Items[j] = l.Items[j], l.Items[i] }

// Treat upper and lower case equally
func (l byName) Less(i, j int) bool {
	return strings.ToLower(l.Items[i].Name) < strings.ToLower(l.Items[j].Name)
}

// By Size
func (l bySize) Len() int           { return len(l.Items) }
func (l bySize) Swap(i, j int)      { l.Items[i], l.Items[j] = l.Items[j], l.Items[i] }
func (l bySize) Less(i, j int) bool { return l.Items[i].Size < l.Items[j].Size }

// By Time
func (l byTime) Len() int           { return len(l.Items) }
func (l byTime) Swap(i, j int)      { l.Items[i], l.Items[j] = l.Items[j], l.Items[i] }
func (l byTime) Less(i, j int) bool { return l.Items[i].ModTime.Before(l.Items[j].ModTime) }

// Add sorting method to "Listing"
// it will apply what's in ".Sort" and ".Order"
func (l Listing) applySort() {
	// Check '.Order' to know how to sort
	if l.Order == "desc" {
		switch l.Sort {
		case "name":
			sort.Sort(sort.Reverse(byName(l)))
		case "size":
			sort.Sort(sort.Reverse(bySize(l)))
		case "time":
			sort.Sort(sort.Reverse(byTime(l)))
		default:
			// If not one of the above, do nothing
			return
		}
	} else { // If we had more Orderings we could add them here
		switch l.Sort {
		case "name":
			sort.Sort(byName(l))
		case "size":
			sort.Sort(bySize(l))
		case "time":
			sort.Sort(byTime(l))
		default:
			// If not one of the above, do nothing
			return
		}
	}
}

func directoryListing(files []os.FileInfo, r *http.Request, canGoUp bool, root string, ignoreIndexes bool, vars interface{}) (Listing, error) {
	var (
		fileinfos           []FileInfo
		dirCount, fileCount int
		urlPath             = r.URL.Path
	)

	for _, f := range files {
		name := f.Name()

		// Directory is not browsable if it contains index file
		if !ignoreIndexes {
			for _, indexName := range middleware.IndexPages {
				if name == indexName {
					return Listing{}, errors.New("Directory contains index file, not browsable!")
				}
			}
		}

		if f.IsDir() {
			name += "/"
			dirCount++
		} else {
			fileCount++
		}

		url := url.URL{Path: "./" + name} // prepend with "./" to fix paths with ':' in the name

		fileinfos = append(fileinfos, FileInfo{
			IsDir:   f.IsDir(),
			Name:    f.Name(),
			Size:    f.Size(),
			URL:     url.String(),
			ModTime: f.ModTime(),
			Mode:    f.Mode(),
		})
	}

	return Listing{
		Name:     path.Base(urlPath),
		Path:     urlPath,
		CanGoUp:  canGoUp,
		Items:    fileinfos,
		NumDirs:  dirCount,
		NumFiles: fileCount,
		Context: middleware.Context{
			Root: http.Dir(root),
			Req:  r,
			URL:  r.URL,
		},
		User: vars,
	}, nil
}

// ServeHTTP implements the middleware.Handler interface.
func (b Browse) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	var bc *Config
	// See if there's a browse configuration to match the path
	for i := range b.Configs {
		if middleware.Path(r.URL.Path).Matches(b.Configs[i].PathScope) {
			bc = &b.Configs[i]
			goto inScope
		}
	}
	return b.Next.ServeHTTP(w, r)
inScope:

	// Browse works on existing directories; delegate everything else
	requestedFilepath := filepath.Join(b.Root, r.URL.Path)
	info, err := os.Stat(requestedFilepath)
	if err != nil {
		switch {
		case os.IsPermission(err):
			return http.StatusForbidden, err
		case os.IsExist(err):
			return http.StatusNotFound, err
		default:
			return b.Next.ServeHTTP(w, r)
		}
	}
	if !info.IsDir() {
		return b.Next.ServeHTTP(w, r)
	}

	// Do not reply to anything else because it might be nonsensical
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		// proceed, noop
	case "PROPFIND", http.MethodOptions:
		return http.StatusNotImplemented, nil
	default:
		return b.Next.ServeHTTP(w, r)
	}

	// Browsing navigation gets messed up if browsing a directory
	// that doesn't end in "/" (which it should, anyway)
	if !strings.HasSuffix(r.URL.Path, "/") {
		http.Redirect(w, r, r.URL.Path+"/", http.StatusTemporaryRedirect)
		return 0, nil
	}

	// Load directory contents
	file, err := os.Open(requestedFilepath)
	if err != nil {
		switch {
		case os.IsPermission(err):
			return http.StatusForbidden, err
		case os.IsExist(err):
			return http.StatusGone, err
		default:
			return http.StatusInternalServerError, err
		}
	}
	defer file.Close()

	files, err := file.Readdir(-1)
	if err != nil {
		switch {
		case os.IsPermission(err):
			return http.StatusForbidden, err
		case os.IsExist(err):
			return http.StatusGone, err
		default:
			return http.StatusInternalServerError, err
		}
	}

	// Determine if user can browse up another folder
	var canGoUp bool
	curPath := strings.TrimSuffix(r.URL.Path, "/")
	for _, other := range b.Configs {
		if strings.HasPrefix(path.Dir(curPath), other.PathScope) {
			canGoUp = true
			break
		}
	}
	// Assemble listing of directory contents
	listing, err := directoryListing(files, r, canGoUp, b.Root, b.IgnoreIndexes, bc.Variables)
	if err != nil { // directory isn't browsable
		return b.Next.ServeHTTP(w, r)
	}

	// Copy the query values into the Listing struct
	listing.Sort, listing.Order = r.URL.Query().Get("sort"), r.URL.Query().Get("order")

	// If the query 'sort' or 'order' is empty, use defaults or any values previously saved in Cookies
	if listing.Sort == "" {
		listing.Sort = "name"
		if sortCookie, sortErr := r.Cookie("sort"); sortErr == nil {
			listing.Sort = sortCookie.Value
		}
	} else { // Save the query value of 'sort' and 'order' as cookies.
		http.SetCookie(w, &http.Cookie{Name: "sort", Value: listing.Sort, Path: bc.PathScope, Secure: r.TLS != nil})
		http.SetCookie(w, &http.Cookie{Name: "order", Value: listing.Order, Path: bc.PathScope, Secure: r.TLS != nil})
	}

	if listing.Order == "" {
		listing.Order = "asc"
		if orderCookie, orderErr := r.Cookie("order"); orderErr == nil {
			listing.Order = orderCookie.Value
		}
	} else {
		http.SetCookie(w, &http.Cookie{Name: "order", Value: listing.Order, Path: bc.PathScope, Secure: r.TLS != nil})
	}

	listing.applySort()

	var buf bytes.Buffer
	// Check if we should provide json
	acceptHeader := strings.Join(r.Header["Accept"], ",")
	if strings.Contains(strings.ToLower(acceptHeader), "application/json") {
		var marsh []byte
		// Check if we are limited
		if limitQuery := r.URL.Query().Get("limit"); limitQuery != "" {
			limit, err := strconv.Atoi(limitQuery)
			if err != nil { // if the 'limit' query can't be interpreted as a number, return err
				return http.StatusBadRequest, err
			}
			// if `limit` is equal or less than len(listing.Items) and bigger than 0, list them
			if limit <= len(listing.Items) && limit > 0 {
				marsh, err = json.Marshal(listing.Items[:limit])
			} else { // if the 'limit' query is empty, or has the wrong value, list everything
				marsh, err = json.Marshal(listing.Items)
			}
			if err != nil {
				return http.StatusInternalServerError, err
			}
		} else { // There's no 'limit' query; list them all
			marsh, err = json.Marshal(listing.Items)
			if err != nil {
				return http.StatusInternalServerError, err
			}
		}

		// Write the marshaled json to buf
		if _, err = buf.Write(marsh); err != nil {
			return http.StatusInternalServerError, err
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")

	} else { // There's no 'application/json' in the 'Accept' header; browse normally
		err = bc.Template.Execute(&buf, listing)
		if err != nil {
			return http.StatusInternalServerError, err
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")

	}

	buf.WriteTo(w)

	return http.StatusOK, nil
}
