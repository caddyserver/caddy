// Package browse provides middleware for listing files in a directory
// when directory path is requested instead of a specific file.
package browse

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/mholt/caddy/caddyhttp/httpserver"
	"github.com/mholt/caddy/caddyhttp/staticfiles"
)

// Browse is an http.Handler that can show a file listing when
// directories in the given paths are specified.
type Browse struct {
	Next          httpserver.Handler
	Configs       []Config
	IgnoreIndexes bool
}

// Config is a configuration for browsing in a particular path.
type Config struct {
	PathScope string
	Root      http.FileSystem
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

	// If ≠0 then Items have been limited to that many elements
	ItemsLimitedTo int

	// Optional custom variables for use in browse templates
	User interface{}

	httpserver.Context
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
func (l bySize) Len() int      { return len(l.Items) }
func (l bySize) Swap(i, j int) { l.Items[i], l.Items[j] = l.Items[j], l.Items[i] }

const directoryOffset = -1 << 31 // = math.MinInt32
func (l bySize) Less(i, j int) bool {
	iSize, jSize := l.Items[i].Size, l.Items[j].Size
	if l.Items[i].IsDir {
		iSize = directoryOffset + iSize
	}
	if l.Items[j].IsDir {
		jSize = directoryOffset + jSize
	}
	return iSize < jSize
}

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

func directoryListing(files []os.FileInfo, canGoUp bool, urlPath string) (Listing, bool) {
	var (
		fileinfos           []FileInfo
		dirCount, fileCount int
		hasIndexFile        bool
	)

	for _, f := range files {
		name := f.Name()

		for _, indexName := range staticfiles.IndexPages {
			if name == indexName {
				hasIndexFile = true
				break
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
			ModTime: f.ModTime().UTC(),
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
	}, hasIndexFile
}

// ServeHTTP determines if the request is for this plugin, and if all prerequisites are met.
// If so, control is handed over to ServeListing.
func (b Browse) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	var bc *Config
	// See if there's a browse configuration to match the path
	for i := range b.Configs {
		if httpserver.Path(r.URL.Path).Matches(b.Configs[i].PathScope) {
			bc = &b.Configs[i]
			goto inScope
		}
	}
	return b.Next.ServeHTTP(w, r)
inScope:

	// Browse works on existing directories; delegate everything else
	requestedFilepath, err := bc.Root.Open(r.URL.Path)
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
	defer requestedFilepath.Close()

	info, err := requestedFilepath.Stat()
	if err != nil {
		switch {
		case os.IsPermission(err):
			return http.StatusForbidden, err
		case os.IsExist(err):
			return http.StatusGone, err
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
		staticfiles.Redirect(w, r, r.URL.Path+"/", http.StatusTemporaryRedirect)
		return 0, nil
	}

	return b.ServeListing(w, r, requestedFilepath, bc)
}

func (b Browse) loadDirectoryContents(requestedFilepath http.File, urlPath string) (*Listing, bool, error) {
	files, err := requestedFilepath.Readdir(-1)
	if err != nil {
		return nil, false, err
	}

	// Determine if user can browse up another folder
	var canGoUp bool
	curPathDir := path.Dir(strings.TrimSuffix(urlPath, "/"))
	for _, other := range b.Configs {
		if strings.HasPrefix(curPathDir, other.PathScope) {
			canGoUp = true
			break
		}
	}

	// Assemble listing of directory contents
	listing, hasIndex := directoryListing(files, canGoUp, urlPath)

	return &listing, hasIndex, nil
}

// handleSortOrder gets and stores for a Listing the 'sort' and 'order',
// and reads 'limit' if given. The latter is 0 if not given.
//
// This sets Cookies.
func (b Browse) handleSortOrder(w http.ResponseWriter, r *http.Request, scope string) (sort string, order string, limit int, err error) {
	sort, order, limitQuery := r.URL.Query().Get("sort"), r.URL.Query().Get("order"), r.URL.Query().Get("limit")

	// If the query 'sort' or 'order' is empty, use defaults or any values previously saved in Cookies
	switch sort {
	case "":
		sort = "name"
		if sortCookie, sortErr := r.Cookie("sort"); sortErr == nil {
			sort = sortCookie.Value
		}
	case "name", "size", "type":
		http.SetCookie(w, &http.Cookie{Name: "sort", Value: sort, Path: scope, Secure: r.TLS != nil})
	}

	switch order {
	case "":
		order = "asc"
		if orderCookie, orderErr := r.Cookie("order"); orderErr == nil {
			order = orderCookie.Value
		}
	case "asc", "desc":
		http.SetCookie(w, &http.Cookie{Name: "order", Value: order, Path: scope, Secure: r.TLS != nil})
	}

	if limitQuery != "" {
		limit, err = strconv.Atoi(limitQuery)
		if err != nil { // if the 'limit' query can't be interpreted as a number, return err
			return
		}
	}

	return
}

// ServeListing returns a formatted view of 'requestedFilepath' contents'.
func (b Browse) ServeListing(w http.ResponseWriter, r *http.Request, requestedFilepath http.File, bc *Config) (int, error) {
	listing, containsIndex, err := b.loadDirectoryContents(requestedFilepath, r.URL.Path)
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
	if containsIndex && !b.IgnoreIndexes { // directory isn't browsable
		return b.Next.ServeHTTP(w, r)
	}
	listing.Context = httpserver.Context{
		Root: bc.Root,
		Req:  r,
		URL:  r.URL,
	}
	listing.User = bc.Variables

	// Copy the query values into the Listing struct
	var limit int
	listing.Sort, listing.Order, limit, err = b.handleSortOrder(w, r, bc.PathScope)
	if err != nil {
		return http.StatusBadRequest, err
	}

	listing.applySort()

	if limit > 0 && limit <= len(listing.Items) {
		listing.Items = listing.Items[:limit]
		listing.ItemsLimitedTo = limit
	}

	var buf *bytes.Buffer
	acceptHeader := strings.ToLower(strings.Join(r.Header["Accept"], ","))
	switch {
	case strings.Contains(acceptHeader, "application/json"):
		if buf, err = b.formatAsJSON(listing, bc); err != nil {
			return http.StatusInternalServerError, err
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")

	default: // There's no 'application/json' in the 'Accept' header; browse normally
		if buf, err = b.formatAsHTML(listing, bc); err != nil {
			return http.StatusInternalServerError, err
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")

	}

	buf.WriteTo(w)

	return http.StatusOK, nil
}

func (b Browse) formatAsJSON(listing *Listing, bc *Config) (*bytes.Buffer, error) {
	marsh, err := json.Marshal(listing.Items)
	if err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)
	_, err = buf.Write(marsh)
	return buf, err
}

func (b Browse) formatAsHTML(listing *Listing, bc *Config) (*bytes.Buffer, error) {
	buf := new(bytes.Buffer)
	err := bc.Template.Execute(buf, listing)
	return buf, err
}
