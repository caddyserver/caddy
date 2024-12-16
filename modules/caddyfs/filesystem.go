package caddyfs

import (
	"encoding/json"
	"fmt"
	"io/fs"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
)

func init() {
	caddy.RegisterModule(Filesystems{})
	httpcaddyfile.RegisterGlobalOption("filesystem", parseFilesystems)
}

type moduleEntry struct {
	Key           string          `json:"name,omitempty"`
	FileSystemRaw json.RawMessage `json:"file_system,omitempty" caddy:"namespace=caddy.fs inline_key=backend"`
	fileSystem    fs.FS
}

// Filesystems loads caddy.fs modules into the global filesystem map
type Filesystems struct {
	Filesystems []*moduleEntry `json:"filesystems"`

	defers []func()
}

func parseFilesystems(d *caddyfile.Dispenser, existingVal any) (any, error) {
	p := &Filesystems{}
	current, ok := existingVal.(*Filesystems)
	if ok {
		p = current
	}
	x := &moduleEntry{}
	err := x.UnmarshalCaddyfile(d)
	if err != nil {
		return nil, err
	}
	p.Filesystems = append(p.Filesystems, x)
	return p, nil
}

// CaddyModule returns the Caddy module information.
func (Filesystems) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.filesystems",
		New: func() caddy.Module { return new(Filesystems) },
	}
}

func (xs *Filesystems) Start() error { return nil }
func (xs *Filesystems) Stop() error  { return nil }

func (xs *Filesystems) Provision(ctx caddy.Context) error {
	// load the filesystem module
	for _, f := range xs.Filesystems {
		if len(f.FileSystemRaw) > 0 {
			mod, err := ctx.LoadModule(f, "FileSystemRaw")
			if err != nil {
				return fmt.Errorf("loading file system module: %v", err)
			}
			f.fileSystem = mod.(fs.FS)
		}
		// register that module
		ctx.Logger().Debug("registering fs", zap.String("fs", f.Key))
		ctx.Filesystems().Register(f.Key, f.fileSystem)
		// remember to unregister the module when we are done
		xs.defers = append(xs.defers, func() {
			ctx.Logger().Debug("unregistering fs", zap.String("fs", f.Key))
			ctx.Filesystems().Unregister(f.Key)
		})
	}
	return nil
}

func (f *Filesystems) Cleanup() error {
	for _, v := range f.defers {
		v()
	}
	return nil
}

func (f *moduleEntry) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		// key required for now
		if !d.Args(&f.Key) {
			return d.ArgErr()
		}
		// get the module json
		if !d.NextArg() {
			return d.ArgErr()
		}
		name := d.Val()
		modID := "caddy.fs." + name
		unm, err := caddyfile.UnmarshalModule(d, modID)
		if err != nil {
			return err
		}
		fsys, ok := unm.(fs.FS)
		if !ok {
			return d.Errf("module %s (%T) is not a supported file system implementation (requires fs.FS)", modID, unm)
		}
		f.FileSystemRaw = caddyconfig.JSONModuleObject(fsys, "backend", name, nil)
	}
	return nil
}
