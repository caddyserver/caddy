// Package browse provides middleware for listing files in a directory
// when directory path is requested instead of a specific file.
package browse

import (
	"bytes"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"
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

// HumanSize returns the size of the file as a human-readable string.
func (fi FileInfo) HumanSize() string {
	return humanize.Bytes(uint64(fi.Size))
}

// HumanModTime returns the modified time of the file as a human-readable string.
func (fi FileInfo) HumanModTime(format string) string {
	return fi.ModTime.Format(format)
}

type fileInfoByName []FileInfo

func (fi fileInfoByName) Len() int           { return len(fi) }
func (fi fileInfoByName) Swap(i, j int)      { fi[i], fi[j] = fi[j], fi[i] }
func (fi fileInfoByName) Less(i, j int) bool { return fi[i].Name < fi[j].Name }

var IndexPages = []string{
	"index.html",
	"index.htm",
	"default.html",
	"default.htm",
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

		// Assemble listing of directory contents
		var fileinfos []FileInfo
		var abort bool // we bail early if we find an index file
		for _, f := range files {
			name := f.Name()

			// Directory is not browseable if it contains index file
			for _, indexName := range IndexPages {
				if name == indexName {
					abort = true
					break
				}
			}
			if abort {
				break
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
		if abort {
			// this dir has an index file, so not browsable
			continue
		}

		sort.Sort(fileInfoByName(fileinfos))

		// Determine if user can browse up another folder
		var canGoUp bool
		curPath := strings.TrimSuffix(r.URL.Path, "/")
		for _, other := range b.Configs {
			if strings.HasPrefix(path.Dir(curPath), other.PathScope) {
				canGoUp = true
				break
			}
		}

		listing := Listing{
			Name:    path.Base(r.URL.Path),
			Path:    r.URL.Path,
			CanGoUp: canGoUp,
			Items:   fileinfos,
		}

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
