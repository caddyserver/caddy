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
	"net/url"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/dustin/go-humanize"
)

func (fsrv *FileServer) directoryListing(files []os.FileInfo, canGoUp bool, urlPath string, repl *caddy.Replacer) browseListing {
	filesToHide := fsrv.transformHidePaths(repl)

	var (
		fileInfos           []fileInfo
		dirCount, fileCount int
	)

	for _, f := range files {
		name := f.Name()

		if fileHidden(name, filesToHide) {
			continue
		}

		isDir := f.IsDir() || isSymlinkTargetDir(f, fsrv.Root, urlPath)

		if isDir {
			name += "/"
			dirCount++
		} else {
			fileCount++
		}

		u := url.URL{Path: "./" + name} // prepend with "./" to fix paths with ':' in the name

		fileInfos = append(fileInfos, fileInfo{
			IsDir:     isDir,
			IsSymlink: isSymlink(f),
			Name:      f.Name(),
			Size:      f.Size(),
			URL:       u.String(),
			ModTime:   f.ModTime().UTC(),
			Mode:      f.Mode(),
		})
	}

	return browseListing{
		Name:     path.Base(urlPath),
		Path:     urlPath,
		CanGoUp:  canGoUp,
		Items:    fileInfos,
		NumDirs:  dirCount,
		NumFiles: fileCount,
	}
}

type browseListing struct {
	// The name of the directory (the last element of the path).
	Name string

	// The full path of the request.
	Path string

	// Whether the parent directory is browseable.
	CanGoUp bool

	// The items (files and folders) in the path.
	Items []fileInfo

	// The number of directories in the listing.
	NumDirs int

	// The number of files (items that aren't directories) in the listing.
	NumFiles int

	// Sort column used
	Sort string

	// Sorting order
	Order string

	// If ≠0 then Items have been limited to that many elements.
	ItemsLimitedTo int

	// If ≠0 then Items starting from that many elements.
	ItemOffset int
}

// Breadcrumbs returns l.Path where every element maps
// the link to the text to display.
func (l browseListing) Breadcrumbs() []crumb {
	var result []crumb

	if len(l.Path) == 0 {
		return result
	}

	// skip trailing slash
	lpath := l.Path
	if lpath[len(lpath)-1] == '/' {
		lpath = lpath[:len(lpath)-1]
	}

	parts := strings.Split(lpath, "/")
	for i := range parts {
		txt := parts[i]
		if i == 0 && parts[i] == "" {
			txt = "/"
		}
		lnk := strings.Repeat("../", len(parts)-i-1)
		result = append(result, crumb{Link: lnk, Text: txt})
	}

	return result
}

func (l *browseListing) applySortAndLimit(sortParam, orderParam, limitParam string, fromParam string) {
	l.Sort = sortParam
	l.Order = orderParam

	if l.Order == "desc" {
		switch l.Sort {
		case sortByName:
			sort.Sort(sort.Reverse(byName(*l)))
		case sortByNameDirFirst:
			sort.Sort(sort.Reverse(byNameDirFirst(*l)))
		case sortBySize:
			sort.Sort(sort.Reverse(bySize(*l)))
		case sortByTime:
			sort.Sort(sort.Reverse(byTime(*l)))
		}
	} else {
		switch l.Sort {
		case sortByName:
			sort.Sort(byName(*l))
		case sortByNameDirFirst:
			sort.Sort(byNameDirFirst(*l))
		case sortBySize:
			sort.Sort(bySize(*l))
		case sortByTime:
			sort.Sort(byTime(*l))
		}
	}

	if fromParam != "" {
		from, _ := strconv.Atoi(fromParam)
		if from > 0 && from <= len(l.Items) {
			l.Items = l.Items[from:]
			l.ItemsFrom = from
		}
	}

	if limitParam != "" {
		limit, _ := strconv.Atoi(limitParam)

		if limit > 0 && limit <= len(l.Items) {
			l.Items = l.Items[:limit]
			l.ItemsLimitedTo = limit
		}
	}
}

// crumb represents part of a breadcrumb menu,
// pairing a link with the text to display.
type crumb struct {
	Link, Text string
}

// fileInfo contains serializable information
// about a file or directory.
type fileInfo struct {
	Name      string      `json:"name"`
	Size      int64       `json:"size"`
	URL       string      `json:"url"`
	ModTime   time.Time   `json:"mod_time"`
	Mode      os.FileMode `json:"mode"`
	IsDir     bool        `json:"is_dir"`
	IsSymlink bool        `json:"is_symlink"`
}

// HumanSize returns the size of the file as a
// human-readable string in IEC format (i.e.
// power of 2 or base 1024).
func (fi fileInfo) HumanSize() string {
	return humanize.IBytes(uint64(fi.Size))
}

// HumanModTime returns the modified time of the file
// as a human-readable string given by format.
func (fi fileInfo) HumanModTime(format string) string {
	return fi.ModTime.Format(format)
}

type byName browseListing
type byNameDirFirst browseListing
type bySize browseListing
type byTime browseListing

func (l byName) Len() int      { return len(l.Items) }
func (l byName) Swap(i, j int) { l.Items[i], l.Items[j] = l.Items[j], l.Items[i] }

func (l byName) Less(i, j int) bool {
	return strings.ToLower(l.Items[i].Name) < strings.ToLower(l.Items[j].Name)
}

func (l byNameDirFirst) Len() int      { return len(l.Items) }
func (l byNameDirFirst) Swap(i, j int) { l.Items[i], l.Items[j] = l.Items[j], l.Items[i] }

func (l byNameDirFirst) Less(i, j int) bool {
	// sort by name if both are dir or file
	if l.Items[i].IsDir == l.Items[j].IsDir {
		return strings.ToLower(l.Items[i].Name) < strings.ToLower(l.Items[j].Name)
	}
	// sort dir ahead of file
	return l.Items[i].IsDir
}

func (l bySize) Len() int      { return len(l.Items) }
func (l bySize) Swap(i, j int) { l.Items[i], l.Items[j] = l.Items[j], l.Items[i] }

func (l bySize) Less(i, j int) bool {
	const directoryOffset = -1 << 31 // = -math.MinInt32

	iSize, jSize := l.Items[i].Size, l.Items[j].Size

	// directory sizes depend on the file system; to
	// provide a consistent experience, put them up front
	// and sort them by name
	if l.Items[i].IsDir {
		iSize = directoryOffset
	}
	if l.Items[j].IsDir {
		jSize = directoryOffset
	}
	if l.Items[i].IsDir && l.Items[j].IsDir {
		return strings.ToLower(l.Items[i].Name) < strings.ToLower(l.Items[j].Name)
	}

	return iSize < jSize
}

func (l byTime) Len() int           { return len(l.Items) }
func (l byTime) Swap(i, j int)      { l.Items[i], l.Items[j] = l.Items[j], l.Items[i] }
func (l byTime) Less(i, j int) bool { return l.Items[i].ModTime.Before(l.Items[j].ModTime) }

const (
	sortByName         = "name"
	sortByNameDirFirst = "name_dir_first"
	sortBySize         = "size"
	sortByTime         = "time"
)
