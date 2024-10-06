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
	"context"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dustin/go-humanize"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func (fsrv *FileServer) directoryListing(ctx context.Context, fileSystem fs.FS, parentModTime time.Time, entries []fs.DirEntry, canGoUp bool, root, urlPath string, repl *caddy.Replacer) *browseTemplateContext {
	filesToHide := fsrv.transformHidePaths(repl)

	name, _ := url.PathUnescape(urlPath)

	tplCtx := &browseTemplateContext{
		Name:         path.Base(name),
		Path:         urlPath,
		CanGoUp:      canGoUp,
		lastModified: parentModTime,
	}

	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			break
		}

		name := entry.Name()

		if fileHidden(name, filesToHide) {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			if c := fsrv.logger.Check(zapcore.ErrorLevel, "could not get info about directory entry"); c != nil {
				c.Write(zap.String("name", entry.Name()), zap.String("root", root))
			}
			continue
		}

		// keep track of the most recently modified item in the listing
		modTime := info.ModTime()
		if tplCtx.lastModified.IsZero() || modTime.After(tplCtx.lastModified) {
			tplCtx.lastModified = modTime
		}

		isDir := entry.IsDir() || fsrv.isSymlinkTargetDir(fileSystem, info, root, urlPath)

		// add the slash after the escape of path to avoid escaping the slash as well
		if isDir {
			name += "/"
			tplCtx.NumDirs++
		} else {
			tplCtx.NumFiles++
		}

		size := info.Size()

		if !isDir {
			// increase the total by the symlink's size, not the target's size,
			// by incrementing before we follow the symlink
			tplCtx.TotalFileSize += size
		}

		fileIsSymlink := isSymlink(info)
		symlinkPath := ""
		if fileIsSymlink {
			path := caddyhttp.SanitizedPathJoin(root, path.Join(urlPath, info.Name()))
			fileInfo, err := fs.Stat(fileSystem, path)
			if err == nil {
				size = fileInfo.Size()
			}

			if fsrv.Browse.RevealSymlinks {
				symLinkTarget, err := filepath.EvalSymlinks(path)
				if err == nil {
					symlinkPath = symLinkTarget
				}
			}

			// An error most likely means the symlink target doesn't exist,
			// which isn't entirely unusual and shouldn't fail the listing.
			// In this case, just use the size of the symlink itself, which
			// was already set above.
		}

		if !isDir {
			// increase the total including the symlink target's size
			tplCtx.TotalFileSizeFollowingSymlinks += size
		}

		u := url.URL{Path: "./" + name} // prepend with "./" to fix paths with ':' in the name

		tplCtx.Items = append(tplCtx.Items, fileInfo{
			IsDir:       isDir,
			IsSymlink:   fileIsSymlink,
			Name:        name,
			Size:        size,
			URL:         u.String(),
			ModTime:     modTime.UTC(),
			Mode:        info.Mode(),
			Tpl:         tplCtx, // a reference up to the template context is useful
			SymlinkPath: symlinkPath,
		})
	}

	// this time is used for the Last-Modified header and comparing If-Modified-Since from client
	// both are expected to be in UTC, so we convert to UTC here
	// see: https://github.com/caddyserver/caddy/issues/6828
	tplCtx.lastModified = tplCtx.lastModified.UTC()
	return tplCtx
}

// browseTemplateContext provides the template context for directory listings.
type browseTemplateContext struct {
	// The name of the directory (the last element of the path).
	Name string `json:"name"`

	// The full path of the request.
	Path string `json:"path"`

	// Whether the parent directory is browsable.
	CanGoUp bool `json:"can_go_up"`

	// The items (files and folders) in the path.
	Items []fileInfo `json:"items,omitempty"`

	// If ≠0 then Items starting from that many elements.
	Offset int `json:"offset,omitempty"`

	// If ≠0 then Items have been limited to that many elements.
	Limit int `json:"limit,omitempty"`

	// The number of directories in the listing.
	NumDirs int `json:"num_dirs"`

	// The number of files (items that aren't directories) in the listing.
	NumFiles int `json:"num_files"`

	// The total size of all files in the listing. Only includes the
	// size of the files themselves, not the size of symlink targets
	// (i.e. the calculation of this value does not follow symlinks).
	TotalFileSize int64 `json:"total_file_size"`

	// The total size of all files in the listing, including the
	// size of the files targeted by symlinks.
	TotalFileSizeFollowingSymlinks int64 `json:"total_file_size_following_symlinks"`

	// Sort column used
	Sort string `json:"sort,omitempty"`

	// Sorting order
	Order string `json:"order,omitempty"`

	// Display format (list or grid)
	Layout string `json:"layout,omitempty"`

	// The most recent file modification date in the listing.
	// Used for HTTP header purposes.
	lastModified time.Time
}

// Breadcrumbs returns l.Path where every element maps
// the link to the text to display.
func (l browseTemplateContext) Breadcrumbs() []crumb {
	if len(l.Path) == 0 {
		return []crumb{}
	}

	// skip trailing slash
	lpath := l.Path
	if lpath[len(lpath)-1] == '/' {
		lpath = lpath[:len(lpath)-1]
	}
	parts := strings.Split(lpath, "/")
	result := make([]crumb, len(parts))
	for i, p := range parts {
		if i == 0 && p == "" {
			p = "/"
		}
		// the directory name could include an encoded slash in its path,
		// so the item name should be unescaped in the loop rather than unescaping the
		// entire path outside the loop.
		p, _ = url.PathUnescape(p)
		lnk := strings.Repeat("../", len(parts)-i-1)
		result[i] = crumb{Link: lnk, Text: p}
	}

	return result
}

func (l *browseTemplateContext) applySortAndLimit(sortParam, orderParam, limitParam string, offsetParam string) {
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

	if offsetParam != "" {
		offset, _ := strconv.Atoi(offsetParam)
		if offset > 0 && offset <= len(l.Items) {
			l.Items = l.Items[offset:]
			l.Offset = offset
		}
	}

	if limitParam != "" {
		limit, _ := strconv.Atoi(limitParam)

		if limit > 0 && limit <= len(l.Items) {
			l.Items = l.Items[:limit]
			l.Limit = limit
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
	Name        string      `json:"name"`
	Size        int64       `json:"size"`
	URL         string      `json:"url"`
	ModTime     time.Time   `json:"mod_time"`
	Mode        os.FileMode `json:"mode"`
	IsDir       bool        `json:"is_dir"`
	IsSymlink   bool        `json:"is_symlink"`
	SymlinkPath string      `json:"symlink_path,omitempty"`

	// a pointer to the template context is useful inside nested templates
	Tpl *browseTemplateContext `json:"-"`
}

// HasExt returns true if the filename has any of the given suffixes, case-insensitive.
func (fi fileInfo) HasExt(exts ...string) bool {
	return slices.ContainsFunc(exts, func(ext string) bool {
		return strings.HasSuffix(strings.ToLower(fi.Name), strings.ToLower(ext))
	})
}

// HumanSize returns the size of the file as a
// human-readable string in IEC format (i.e.
// power of 2 or base 1024).
func (fi fileInfo) HumanSize() string {
	return humanize.IBytes(uint64(fi.Size))
}

// HumanTotalFileSize returns the total size of all files
// in the listing as a human-readable string in IEC format
// (i.e. power of 2 or base 1024).
func (btc browseTemplateContext) HumanTotalFileSize() string {
	return humanize.IBytes(uint64(btc.TotalFileSize))
}

// HumanTotalFileSizeFollowingSymlinks is the same as HumanTotalFileSize
// except the returned value reflects the size of symlink targets.
func (btc browseTemplateContext) HumanTotalFileSizeFollowingSymlinks() string {
	return humanize.IBytes(uint64(btc.TotalFileSizeFollowingSymlinks))
}

// HumanModTime returns the modified time of the file
// as a human-readable string given by format.
func (fi fileInfo) HumanModTime(format string) string {
	return fi.ModTime.Format(format)
}

type (
	byName         browseTemplateContext
	byNameDirFirst browseTemplateContext
	bySize         browseTemplateContext
	byTime         browseTemplateContext
)

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
	sortByNameDirFirst = "namedirfirst"
	sortBySize         = "size"
	sortByTime         = "time"

	sortOrderAsc  = "asc"
	sortOrderDesc = "desc"
)
