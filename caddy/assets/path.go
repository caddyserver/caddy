package assets

import (
	"os"
	"path/filepath"
	"runtime"
)

// Path returns the path to the folder
// where the application may store data. This
// currently resolves to ~/.caddy
func Path() string {
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
