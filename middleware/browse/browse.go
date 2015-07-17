// Package browse provides middleware for listing files in a directory
// when directory path is requested instead of a specific file.
package browse

import (
	"bytes"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"
	"text/template"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/mholt/caddy/middleware"
)

// Browse is an http.Handler that can show a file listing when
// directories in the given paths are specified.
type Browse struct {
	Next    middleware.Handler
	Root    string
	Configs []Config
}

// Config is a configuration for browsing in a particular path.
type Config struct {
	PathScope string
	Template  *template.Template
}

// A Listing is used to fill out a template.
type Listing struct {
	// The name of the directory (the last element of the path)
	Name string

	// The full path of the request
	Path string

	// Whether the parent directory is browsable
	CanGoUp bool

	// The items (files and folders) in the path
	Items []FileInfo

	// Which sorting order is used
	Sort string

	// And which order
	Order string

	middleware.Context
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
func (l byTime) Less(i, j int) bool { return l.Items[i].ModTime.Unix() < l.Items[j].ModTime.Unix() }

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

// HumanSize returns the size of the file as a human-readable string.
func (fi FileInfo) HumanSize() string {
	return humanize.Bytes(uint64(fi.Size))
}

// HumanModTime returns the modified time of the file as a human-readable string.
func (fi FileInfo) HumanModTime(format string) string {
	return fi.ModTime.Format(format)
}

var IndexPages = []string{
	"index.html",
	"index.htm",
	"default.html",
	"default.htm",
}

func directoryListing(files []os.FileInfo, r *http.Request, canGoUp bool, root string) (Listing, error) {
	var fileinfos []FileInfo
	var urlPath = r.URL.Path
	for _, f := range files {
		name := f.Name()

		// Directory is not browsable if it contains index file
		for _, indexName := range IndexPages {
			if name == indexName {
				return Listing{}, errors.New("Directory contains index file, not browsable!")
			}
		}

		if f.IsDir() {
			name += "/"
		}

		url := url.URL{Path: name}

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
		Name:    path.Base(urlPath),
		Path:    urlPath,
		CanGoUp: canGoUp,
		Items:   fileinfos,
		Context: middleware.Context{
			Root: http.Dir(root),
			Req:  r,
			URL:  r.URL,
		},
	}, nil
}

// ServeHTTP implements the middleware.Handler interface.
func (b Browse) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	filename := b.Root + r.URL.Path

	info, err := os.Stat(filename)
	if err != nil {
		return b.Next.ServeHTTP(w, r)
	}

	if !info.IsDir() {
		return b.Next.ServeHTTP(w, r)
	}

	// See if there's a browse configuration to match the path
	for _, bc := range b.Configs {
		if !middleware.Path(r.URL.Path).Matches(bc.PathScope) {
			continue
		}

		// Browsing navigation gets messed up if browsing a directory
		// that doesn't end in "/" (which it should, anyway)
		if r.URL.Path[len(r.URL.Path)-1] != '/' {
			http.Redirect(w, r, r.URL.Path+"/", http.StatusTemporaryRedirect)
			return 0, nil
		}

		// Load directory contents
		file, err := os.Open(b.Root + r.URL.Path)
		if err != nil {
			if os.IsPermission(err) {
				return http.StatusForbidden, err
			}
			return http.StatusNotFound, err
		}
		defer file.Close()

		files, err := file.Readdir(-1)
		if err != nil {
			return http.StatusForbidden, err
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
		listing, err := directoryListing(files, r, canGoUp, b.Root)
		if err != nil { // directory isn't browsable
			continue
		}

		// Get the query vales and store them in the Listing struct
		listing.Sort, listing.Order = r.URL.Query().Get("sort"), r.URL.Query().Get("order")

		// If the query 'sort' is empty, default to "name" and "asc"
		if listing.Sort == "" {
			listing.Sort = "name"
			listing.Order = "asc"
		}

		// Apply the sorting
		listing.applySort()

		var buf bytes.Buffer
		err = bc.Template.Execute(&buf, listing)
		if err != nil {
			return http.StatusInternalServerError, err
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		buf.WriteTo(w)

		return http.StatusOK, nil
	}

	// Didn't qualify; pass-thru
	return b.Next.ServeHTTP(w, r)
}
