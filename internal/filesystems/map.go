package filesystems

import (
	"io/fs"
	"strings"
	"sync"
)

const (
	DefaultFileSystemKey = "default"
)

var DefaultFileSystem = &wrapperFs{key: DefaultFileSystemKey, FS: OsFS{}}

// wrapperFs exists so can easily add to wrapperFs down the line
type wrapperFs struct {
	key string
	fs.FS
}

// FileSystemMap stores a map of filesystems
// the empty key will be overwritten to be the default key
// it includes a default filesystem, based off the os fs
type FileSystemMap struct {
	m sync.Map
}

// note that the first invocation of key cannot be called in a racy context.
func (f *FileSystemMap) key(k string) string {
	if k == "" {
		k = DefaultFileSystemKey
	}
	return k
}

// Register will add the filesystem with key to later be retrieved
// A call with a nil fs will call unregister, ensuring that a call to Default() will never be nil
func (f *FileSystemMap) Register(k string, v fs.FS) {
	k = f.key(k)
	if v == nil {
		f.Unregister(k)
		return
	}
	f.m.Store(k, &wrapperFs{key: k, FS: v})
}

// Unregister will remove the filesystem with key from the filesystem map
// if the key is the default key, it will set the default to the osFS instead of deleting it
// modules should call this on cleanup to be safe
func (f *FileSystemMap) Unregister(k string) {
	k = f.key(k)
	if k == DefaultFileSystemKey {
		f.m.Store(k, DefaultFileSystem)
	} else {
		f.m.Delete(k)
	}
}

// Get will get a filesystem with a given key
func (f *FileSystemMap) Get(k string) (v fs.FS, ok bool) {
	k = f.key(k)
	c, ok := f.m.Load(strings.TrimSpace(k))
	if !ok {
		if k == DefaultFileSystemKey {
			f.m.Store(k, DefaultFileSystem)
			return DefaultFileSystem, true
		}
		return nil, ok
	}
	return c.(fs.FS), true
}

// Default will get the default filesystem in the filesystem map
func (f *FileSystemMap) Default() fs.FS {
	val, _ := f.Get(DefaultFileSystemKey)
	return val
}
