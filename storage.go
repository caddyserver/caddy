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

package caddy

import (
	"os"
	"path/filepath"

	"github.com/mholt/certmagic"
)

// StorageConverter is a type that can convert itself
// to a valid, usable certmagic.Storage value. (The
// value might be short-lived.) This interface allows
// us to adapt any CertMagic storage implementation
// into a consistent API for Caddy configuration.
type StorageConverter interface {
	CertMagicStorage() (certmagic.Storage, error)
}

// dataDir returns a directory path that is suitable for storage.
// If the location cannot be determined, use current directory.
func dataDir() string {
	baseDir, err := os.UserConfigDir()
	if err != nil {
		baseDir, err = os.Getwd()
		if err != nil {
			panic("failed to locate current directory")
		}
	}
	return filepath.Join(baseDir, "caddy")
}
