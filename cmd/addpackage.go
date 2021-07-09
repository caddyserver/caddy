package caddycmd

import (
	"fmt"
	"net/url"
	"os"
	"runtime"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

func cmdAddPackage(fl Flags) (int, error) {
	l := caddy.Log()
	packageName := fl.Args()[0]
	if packageName == "" {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("package name must be specified")
	}
	thisExecPath, err := os.Executable()
	if err != nil {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("determining current executable path: %v", err)
	}
	thisExecStat, err := os.Stat(thisExecPath)
	if err != nil {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("retrieving current executable permission bits: %v", err)
	}
	l.Info("this executable will be replaced", zap.String("path", thisExecPath))

	// get the list of nonstandard plugins
	_, nonstandard, _, err := getModules()
	if err != nil {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("unable to enumerate installed plugins: %v", err)
	}
	pluginPkgs, err := getPluginPackages(nonstandard)
	if err != nil {
		return caddy.ExitCodeFailedStartup, err
	}

	if _, ok := pluginPkgs[packageName]; ok {
		// package already exists
		return caddy.ExitCodeFailedStartup, fmt.Errorf("package is already added")
	}

	// build the request URL to download this custom build
	qs := url.Values{
		"os":   {runtime.GOOS},
		"arch": {runtime.GOARCH},
	}
	qs.Add("p", packageName)

	resp, err := downloadBuild(qs)
	if err != nil {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("download failed: %v", err)
	}
	defer resp.Body.Close()

	// back up the current binary, in case something goes wrong we can replace it
	backupExecPath := thisExecPath + ".tmp"
	l.Info("build acquired; backing up current executable",
		zap.String("current_path", thisExecPath),
		zap.String("backup_path", backupExecPath))
	err = os.Rename(thisExecPath, backupExecPath)
	if err != nil {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("backing up current binary: %v", err)
	}
	defer func() {
		if err != nil {
			err2 := os.Rename(backupExecPath, thisExecPath)
			if err2 != nil {
				l.Error("restoring original executable failed; will need to be restored manually",
					zap.String("backup_path", backupExecPath),
					zap.String("original_path", thisExecPath),
					zap.Error(err2))
			}
		}
	}()

	// download the file; do this in a closure to close reliably before we execute it
	err = writeCaddyBinary(thisExecPath, &resp.Body, thisExecStat)
	if err != nil {
		return caddy.ExitCodeFailedStartup, err
	}
	l.Info("download successful; displaying new binary details", zap.String("location", thisExecPath))

	// use the new binary to print out version and module info
	fmt.Print("\nModule versions:\n\n")
	if err = listModules(thisExecPath); err != nil {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("download succeeded, but unable to execute: %v", err)
	}

	// clean up the backup file
	err = os.Remove(backupExecPath)
	if err != nil {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("download succeeded, but unable to clean up backup binary: %v", err)
	}

	return caddy.ExitCodeSuccess, nil
}
