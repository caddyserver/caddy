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

package filestorage

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/certmagic"
)

func init() {
	caddy.RegisterModule(FileStorage{})
}

// FileStorage is a certmagic.Storage wrapper for certmagic.FileStorage.
type FileStorage struct {
	// The base path to the folder used for storage.
	Root string `json:"root,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (FileStorage) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.storage.file_system",
		New: func() caddy.Module { return new(FileStorage) },
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

// Interface guards
var (
	_ caddy.StorageConverter = (*FileStorage)(nil)
	_ caddyfile.Unmarshaler  = (*FileStorage)(nil)
)
