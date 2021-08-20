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
	"runtime"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

// StorageConverter is a type that can convert itself
// to a valid, usable certmagic.Storage value. (The
// value might be short-lived.) This interface allows
// us to adapt any CertMagic storage implementation
// into a consistent API for Caddy configuration.
type StorageConverter interface {
	CertMagicStorage() (certmagic.Storage, error)
}

// HomeDir returns the best guess of the current user's home
// directory from environment variables. If unknown, "." (the
// current directory) is returned instead, except GOOS=android,
// which returns "/sdcard".
func HomeDir() string {
	home := homeDirUnsafe()
	if home == "" && runtime.GOOS == "android" {
		home = "/sdcard"
	}
	if home == "" {
		home = "."
	}
	return home
}

// homeDirUnsafe is a low-level function that returns
// the user's home directory from environment
// variables. Careful: if it cannot be determined, an
// empty string is returned. If not accounting for
// that case, use HomeDir() instead; otherwise you
// may end up using the root of the file system.
func homeDirUnsafe() string {
	home := os.Getenv("HOME")
	if home == "" && runtime.GOOS == "windows" {
		drive := os.Getenv("HOMEDRIVE")
		path := os.Getenv("HOMEPATH")
		home = drive + path
		if drive == "" || path == "" {
			home = os.Getenv("USERPROFILE")
		}
	}
	if home == "" && runtime.GOOS == "plan9" {
		home = os.Getenv("home")
	}
	return home
}

// AppConfigDir returns the directory where to store user's config.
//
// If XDG_CONFIG_HOME is set, it returns: $XDG_CONFIG_HOME/caddy.
// Otherwise, os.UserConfigDir() is used; if successful, it appends
// "Caddy" (Windows & Mac) or "caddy" (every other OS) to the path.
// If it returns an error, the fallback path "./caddy" is returned.
//
// The config directory is not guaranteed to be different from
// AppDataDir().
//
// Unlike os.UserConfigDir(), this function prefers the
// XDG_CONFIG_HOME env var on all platforms, not just Unix.
//
// Ref: https://specifications.freedesktop.org/basedir-spec/basedir-spec-latest.html
func AppConfigDir() string {
	if basedir := os.Getenv("XDG_CONFIG_HOME"); basedir != "" {
		return filepath.Join(basedir, "caddy")
	}
	basedir, err := os.UserConfigDir()
	if err != nil {
		Log().Warn("unable to determine directory for user configuration; falling back to current directory", zap.Error(err))
		return "./caddy"
	}
	subdir := "caddy"
	switch runtime.GOOS {
	case "windows", "darwin":
		subdir = "Caddy"
	}
	return filepath.Join(basedir, subdir)
}

// AppDataDir returns a directory path that is suitable for storing
// application data on disk. It uses the environment for finding the
// best place to store data, and appends a "caddy" or "Caddy" (depending
// on OS and environment) subdirectory.
//
// For a base directory path:
// If XDG_DATA_HOME is set, it returns: $XDG_DATA_HOME/caddy; otherwise,
// on Windows it returns: %AppData%/Caddy,
// on Mac: $HOME/Library/Application Support/Caddy,
// on Plan9: $home/lib/caddy,
// on Android: $HOME/caddy,
// and on everything else: $HOME/.local/share/caddy.
//
// If a data directory cannot be determined, it returns "./caddy"
// (this is not ideal, and the environment should be fixed).
//
// The data directory is not guaranteed to be different from AppConfigDir().
//
// Ref: https://specifications.freedesktop.org/basedir-spec/basedir-spec-latest.html
func AppDataDir() string {
	if basedir := os.Getenv("XDG_DATA_HOME"); basedir != "" {
		return filepath.Join(basedir, "caddy")
	}
	switch runtime.GOOS {
	case "windows":
		appData := os.Getenv("AppData")
		if appData != "" {
			return filepath.Join(appData, "Caddy")
		}
	case "darwin":
		home := homeDirUnsafe()
		if home != "" {
			return filepath.Join(home, "Library", "Application Support", "Caddy")
		}
	case "plan9":
		home := homeDirUnsafe()
		if home != "" {
			return filepath.Join(home, "lib", "caddy")
		}
	case "android":
		home := homeDirUnsafe()
		if home != "" {
			return filepath.Join(home, "caddy")
		}
	default:
		home := homeDirUnsafe()
		if home != "" {
			return filepath.Join(home, ".local", "share", "caddy")
		}
	}
	return "./caddy"
}

// ConfigAutosavePath is the default path to which the last config will be persisted.
var ConfigAutosavePath = filepath.Join(AppConfigDir(), "autosave.json")

// DefaultStorage is Caddy's default storage module.
var DefaultStorage = &certmagic.FileStorage{Path: AppDataDir()}
