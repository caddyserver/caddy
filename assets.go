package caddy

import (
	"os"
	"path/filepath"
	"runtime"
)

// AssetsPath returns the path to the folder
// where the application may store data. If
// CADDYPATH env variable is set, that value
// is used. Otherwise, the path is the result
// of evaluating "$HOME/.caddy".
func AssetsPath() string {
	if caddyPath := os.Getenv("CADDYPATH"); caddyPath != "" {
		return caddyPath
	}
	return filepath.Join(userHomeDir(), ".caddy")
}

// userHomeDir returns the user's home directory according to
// environment variables.
//
// Credit: http://stackoverflow.com/a/7922977/1048862
func userHomeDir() string {
	if runtime.GOOS == "windows" {
		home := os.Getenv("HOMEDRIVE") + os.Getenv("HOMEPATH")
		if home == "" {
			home = os.Getenv("USERPROFILE")
		}
		return home
	}
	return os.Getenv("HOME")
}
