package filesystems

import (
	"io/fs"
	"strings"
	"sync"
)

const (
	DefaultFilesystemKey = "default"
)

var DefaultFilesystem = &wrapperFs{key: DefaultFilesystemKey, FS: OsFS{}}

// wrapperFs exists so can easily add to wrapperFs down the line
type wrapperFs struct {
	key string
	fs.FS
}

// FilesystemMap stores a map of filesystems
// the empty key will be overwritten to be the default key
// it includes a default filesystem, based off the os fs
type FilesystemMap struct {
	m sync.Map
}

// note that the first invocation of key cannot be called in a racy context.
func (f *FilesystemMap) key(k string) string {
	if k == "" {
		k = DefaultFilesystemKey
	}
	return k
}

// Register will add the filesystem with key to later be retrieved
// A call with a nil fs will call unregister, ensuring that a call to Default() will never be nil
func (f *FilesystemMap) Register(k string, v fs.FS) {
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
func (f *FilesystemMap) Unregister(k string) {
	k = f.key(k)
	if k == DefaultFilesystemKey {
		f.m.Store(k, DefaultFilesystem)
	} else {
		f.m.Delete(k)
	}
}

// Get will get a filesystem with a given key
func (f *FilesystemMap) Get(k string) (v fs.FS, ok bool) {
	k = f.key(k)
	c, ok := f.m.Load(strings.TrimSpace(k))
	if !ok {
		if k == DefaultFilesystemKey {
			f.m.Store(k, DefaultFilesystem)
			return DefaultFilesystem, true
		}
		return nil, ok
	}
	return c.(fs.FS), true
}

// Default will get the default filesystem in the filesystem map
func (f *FilesystemMap) Default() fs.FS {
	val, _ := f.Get(DefaultFilesystemKey)
	return val
}
