// Copyright 2015 Matthew Holt
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

package certmagic

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
)

// FileStorage facilitates forming file paths derived from a root
// directory. It is used to get file paths in a consistent,
// cross-platform way or persisting ACME assets on the file system.
type FileStorage struct {
	Path string
}

// Exists returns true if key exists in fs.
func (fs FileStorage) Exists(key string) bool {
	_, err := os.Stat(fs.filename(key))
	return !os.IsNotExist(err)
}

// Store saves value at key.
func (fs FileStorage) Store(key string, value []byte) error {
	filename := fs.filename(key)
	err := os.MkdirAll(filepath.Dir(filename), 0700)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filename, value, 0600)
}

// Load retrieves the value at key.
func (fs FileStorage) Load(key string) ([]byte, error) {
	contents, err := ioutil.ReadFile(fs.filename(key))
	if os.IsNotExist(err) {
		return nil, ErrNotExist(err)
	}
	return contents, nil
}

// Delete deletes the value at key.
// TODO: Delete any empty folders caused by this operation
func (fs FileStorage) Delete(key string) error {
	err := os.Remove(fs.filename(key))
	if os.IsNotExist(err) {
		return ErrNotExist(err)
	}
	return err
}

// List returns all keys that match prefix.
func (fs FileStorage) List(prefix string) ([]string, error) {
	d, err := os.Open(fs.filename(prefix))
	if os.IsNotExist(err) {
		return nil, ErrNotExist(err)
	}
	if err != nil {
		return nil, err
	}
	defer d.Close()
	return d.Readdirnames(-1)
}

// Stat returns information about key.
func (fs FileStorage) Stat(key string) (KeyInfo, error) {
	fi, err := os.Stat(fs.filename(key))
	if os.IsNotExist(err) {
		return KeyInfo{}, ErrNotExist(err)
	}
	if err != nil {
		return KeyInfo{}, err
	}
	return KeyInfo{
		Key:      key,
		Modified: fi.ModTime(),
		Size:     fi.Size(),
	}, nil
}

func (fs FileStorage) filename(key string) string {
	return filepath.Join(fs.Path, filepath.FromSlash(key))
}

// homeDir returns the best guess of the current user's home
// directory from environment variables. If unknown, "." (the
// current directory) is returned instead.
func homeDir() string {
	home := os.Getenv("HOME")
	if home == "" && runtime.GOOS == "windows" {
		drive := os.Getenv("HOMEDRIVE")
		path := os.Getenv("HOMEPATH")
		home = drive + path
		if drive == "" || path == "" {
			home = os.Getenv("USERPROFILE")
		}
	}
	if home == "" {
		home = "."
	}
	return home
}

func dataDir() string {
	baseDir := filepath.Join(homeDir(), ".local", "share")
	if xdgData := os.Getenv("XDG_DATA_HOME"); xdgData != "" {
		baseDir = xdgData
	}
	return filepath.Join(baseDir, "certmagic")
}

var _ Storage = FileStorage{}
