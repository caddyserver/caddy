package filesystems

import (
	"io/fs"
	"os"
	"path/filepath"
)

// OsFS is a simple fs.FS implementation that uses the local
// file system. (We do not use os.DirFS because we do our own
// rooting or path prefixing without being constrained to a single
// root folder. The standard os.DirFS implementation is problematic
// since roots can be dynamic in our application.)
//
// OsFS also implements fs.StatFS, fs.GlobFS, fs.ReadDirFS, and fs.ReadFileFS.
type OsFS struct{}

func (OsFS) Open(name string) (fs.File, error)          { return os.Open(name) }
func (OsFS) Stat(name string) (fs.FileInfo, error)      { return os.Stat(name) }
func (OsFS) Glob(pattern string) ([]string, error)      { return filepath.Glob(pattern) }
func (OsFS) ReadDir(name string) ([]fs.DirEntry, error) { return os.ReadDir(name) }
func (OsFS) ReadFile(name string) ([]byte, error)       { return os.ReadFile(name) }

var (
	_ fs.StatFS     = (*OsFS)(nil)
	_ fs.GlobFS     = (*OsFS)(nil)
	_ fs.ReadDirFS  = (*OsFS)(nil)
	_ fs.ReadFileFS = (*OsFS)(nil)
)
