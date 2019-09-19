package filestorage

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/mholt/certmagic"
)

func init() {
	caddy.RegisterModule(FileStorage{})
}

// FileStorage is a certmagic.Storage wrapper for certmagic.FileStorage.
type FileStorage struct {
	Root string `json:"root,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (FileStorage) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		Name: "caddy.storage.file_system",
		New:  func() caddy.Module { return new(FileStorage) },
	}
}

// CertMagicStorage converts s to a certmagic.Storage instance.
func (s FileStorage) CertMagicStorage() (certmagic.Storage, error) {
	return &certmagic.FileStorage{Path: s.Root}, nil
}

// UnmarshalCaddyfile sets up the storage module from Caddyfile tokens.
func (s *FileStorage) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if !d.Next() {
		return d.Err("expected tokens")
	}
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		if !d.NextArg() {
			return d.ArgErr()
		}
		s.Root = d.Val()
		if d.NextArg() {
			return d.ArgErr()
		}
	}
	return nil
}

// Interface guard
var _ caddy.StorageConverter = (*FileStorage)(nil)
