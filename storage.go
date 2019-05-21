package caddy2

import (
	"os"
	"path/filepath"
	"runtime"

	"github.com/mholt/certmagic"
)

func init() {
	RegisterModule(Module{
		Name: "caddy.storage.file_system",
		New:  func() interface{} { return new(fileStorage) },
	})
}

// StorageConverter is a type that can convert itself
// to a valid, usable certmagic.Storage value. (The
// value might be short-lived.) This interface allows
// us to adapt any CertMagic storage implementation
// into a consistent API for Caddy configuration.
type StorageConverter interface {
	CertMagicStorage() (certmagic.Storage, error)
}

// fileStorage is a certmagic.Storage wrapper for certmagic.FileStorage.
type fileStorage struct {
	Root string `json:"root"`
}

func (s fileStorage) CertMagicStorage() (certmagic.Storage, error) {
	return &certmagic.FileStorage{Path: s.Root}, nil
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

// dataDir returns a directory path that is suitable for storage.
// https://specifications.freedesktop.org/basedir-spec/basedir-spec-latest.html#variables
func dataDir() string {
	baseDir := filepath.Join(homeDir(), ".local", "share")
	if xdgData := os.Getenv("XDG_DATA_HOME"); xdgData != "" {
		baseDir = xdgData
	}
	return filepath.Join(baseDir, "caddy")
}

// Interface guard
var _ StorageConverter = fileStorage{}
