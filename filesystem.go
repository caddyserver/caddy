package caddy

import "io/fs"

type FileSystems interface {
	Register(k string, v fs.FS)
	Unregister(k string)
	Get(k string) (v fs.FS, ok bool)
	Default() fs.FS
}
