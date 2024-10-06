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

package caddycmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"runtime/debug"
	"strings"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
)

func cmdUpgrade(fl Flags) (int, error) {
	_, nonstandard, _, err := getModules()
	if err != nil {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("unable to enumerate installed plugins: %v", err)
	}
	pluginPkgs, err := getPluginPackages(nonstandard)
	if err != nil {
		return caddy.ExitCodeFailedStartup, err
	}

	return upgradeBuild(pluginPkgs, fl)
}

func splitModule(arg string) (module, version string, err error) {
	const versionSplit = "@"

	// accommodate module paths that have @ in them, but we can only tolerate that if there's also
	// a version, otherwise we don't know if it's a version separator or part of the file path
	lastVersionSplit := strings.LastIndex(arg, versionSplit)
	if lastVersionSplit < 0 {
		module = arg
	} else {
		module, version = arg[:lastVersionSplit], arg[lastVersionSplit+1:]
	}

	if module == "" {
		err = fmt.Errorf("module name is required")
	}

	return
}

func cmdAddPackage(fl Flags) (int, error) {
	if len(fl.Args()) == 0 {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("at least one package name must be specified")
	}
	_, nonstandard, _, err := getModules()
	if err != nil {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("unable to enumerate installed plugins: %v", err)
	}
	pluginPkgs, err := getPluginPackages(nonstandard)
	if err != nil {
		return caddy.ExitCodeFailedStartup, err
	}

	for _, arg := range fl.Args() {
		module, version, err := splitModule(arg)
		if err != nil {
			return caddy.ExitCodeFailedStartup, fmt.Errorf("invalid module name: %v", err)
		}
		// only allow a version to be specified if it's different from the existing version
		if _, ok := pluginPkgs[module]; ok && !(version != "" && pluginPkgs[module].Version != version) {
			return caddy.ExitCodeFailedStartup, fmt.Errorf("package is already added")
		}
		pluginPkgs[module] = pluginPackage{Version: version, Path: module}
	}

	return upgradeBuild(pluginPkgs, fl)
}

func cmdRemovePackage(fl Flags) (int, error) {
	if len(fl.Args()) == 0 {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("at least one package name must be specified")
	}
	_, nonstandard, _, err := getModules()
	if err != nil {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("unable to enumerate installed plugins: %v", err)
	}
	pluginPkgs, err := getPluginPackages(nonstandard)
	if err != nil {
		return caddy.ExitCodeFailedStartup, err
	}

	for _, arg := range fl.Args() {
		module, _, err := splitModule(arg)
		if err != nil {
			return caddy.ExitCodeFailedStartup, fmt.Errorf("invalid module name: %v", err)
		}
		if _, ok := pluginPkgs[module]; !ok {
			// package does not exist
			return caddy.ExitCodeFailedStartup, fmt.Errorf("package is not added")
		}
		delete(pluginPkgs, arg)
	}

	return upgradeBuild(pluginPkgs, fl)
}

func upgradeBuild(pluginPkgs map[string]pluginPackage, fl Flags) (int, error) {
	l := caddy.Log()

	thisExecPath, err := os.Executable()
	if err != nil {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("determining current executable path: %v", err)
	}
	thisExecStat, err := os.Stat(thisExecPath)
	if err != nil {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("retrieving current executable permission bits: %v", err)
	}
	if thisExecStat.Mode()&os.ModeSymlink == os.ModeSymlink {
		symSource := thisExecPath
		// we are a symlink; resolve it
		thisExecPath, err = filepath.EvalSymlinks(thisExecPath)
		if err != nil {
			return caddy.ExitCodeFailedStartup, fmt.Errorf("resolving current executable symlink: %v", err)
		}
		l.Info("this executable is a symlink", zap.String("source", symSource), zap.String("target", thisExecPath))
	}
	l.Info("this executable will be replaced", zap.String("path", thisExecPath))

	// build the request URL to download this custom build
	qs := url.Values{
		"os":   {runtime.GOOS},
		"arch": {runtime.GOARCH},
	}
	for _, pkgInfo := range pluginPkgs {
		qs.Add("p", pkgInfo.String())
	}

	// initiate the build
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
		return caddy.ExitCodeFailedStartup, fmt.Errorf("download succeeded, but unable to execute 'caddy list-modules': %v", err)
	}
	fmt.Println("\nVersion:")
	if err = showVersion(thisExecPath); err != nil {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("download succeeded, but unable to execute 'caddy version': %v", err)
	}
	fmt.Println()

	// clean up the backup file
	if !fl.Bool("keep-backup") {
		if err = removeCaddyBinary(backupExecPath); err != nil {
			return caddy.ExitCodeFailedStartup, fmt.Errorf("download succeeded, but unable to clean up backup binary: %v", err)
		}
	} else {
		l.Info("skipped cleaning up the backup file", zap.String("backup_path", backupExecPath))
	}

	l.Info("upgrade successful; please restart any running Caddy instances", zap.String("executable", thisExecPath))

	return caddy.ExitCodeSuccess, nil
}

func getModules() (standard, nonstandard, unknown []moduleInfo, err error) {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		err = fmt.Errorf("no build info")
		return
	}

	for _, modID := range caddy.Modules() {
		modInfo, err := caddy.GetModule(modID)
		if err != nil {
			// that's weird, shouldn't happen
			unknown = append(unknown, moduleInfo{caddyModuleID: modID, err: err})
			continue
		}

		// to get the Caddy plugin's version info, we need to know
		// the package that the Caddy module's value comes from; we
		// can use reflection but we need a non-pointer value (I'm
		// not sure why), and since New() should return a pointer
		// value, we need to dereference it first
		iface := any(modInfo.New())
		if rv := reflect.ValueOf(iface); rv.Kind() == reflect.Ptr {
			iface = reflect.New(reflect.TypeOf(iface).Elem()).Elem().Interface()
		}
		modPkgPath := reflect.TypeOf(iface).PkgPath()

		// now we find the Go module that the Caddy module's package
		// belongs to; we assume the Caddy module package path will
		// be prefixed by its Go module path, and we will choose the
		// longest matching prefix in case there are nested modules
		var matched *debug.Module
		for _, dep := range bi.Deps {
			if strings.HasPrefix(modPkgPath, dep.Path) {
				if matched == nil || len(dep.Path) > len(matched.Path) {
					matched = dep
				}
			}
		}

		caddyModGoMod := moduleInfo{caddyModuleID: modID, goModule: matched}

		if strings.HasPrefix(modPkgPath, caddy.ImportPath) {
			standard = append(standard, caddyModGoMod)
		} else {
			nonstandard = append(nonstandard, caddyModGoMod)
		}
	}
	return
}

func listModules(path string) error {
	cmd := exec.Command(path, "list-modules", "--versions", "--skip-standard")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func showVersion(path string) error {
	cmd := exec.Command(path, "version")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func downloadBuild(qs url.Values) (*http.Response, error) {
	l := caddy.Log()
	l.Info("requesting build",
		zap.String("os", qs.Get("os")),
		zap.String("arch", qs.Get("arch")),
		zap.Strings("packages", qs["p"]))
	resp, err := http.Get(fmt.Sprintf("%s?%s", downloadPath, qs.Encode()))
	if err != nil {
		return nil, fmt.Errorf("secure request failed: %v", err)
	}
	if resp.StatusCode >= 400 {
		var details struct {
			StatusCode int `json:"status_code"`
			Error      struct {
				Message string `json:"message"`
				ID      string `json:"id"`
			} `json:"error"`
		}
		err2 := json.NewDecoder(resp.Body).Decode(&details)
		if err2 != nil {
			return nil, fmt.Errorf("download and error decoding failed: HTTP %d: %v", resp.StatusCode, err2)
		}
		return nil, fmt.Errorf("download failed: HTTP %d: %s (id=%s)", resp.StatusCode, details.Error.Message, details.Error.ID)
	}
	return resp, nil
}

func getPluginPackages(modules []moduleInfo) (map[string]pluginPackage, error) {
	pluginPkgs := make(map[string]pluginPackage)
	for _, mod := range modules {
		if mod.goModule.Replace != nil {
			return nil, fmt.Errorf("cannot auto-upgrade when Go module has been replaced: %s => %s",
				mod.goModule.Path, mod.goModule.Replace.Path)
		}
		pluginPkgs[mod.goModule.Path] = pluginPackage{Version: mod.goModule.Version, Path: mod.goModule.Path}
	}
	return pluginPkgs, nil
}

func writeCaddyBinary(path string, body *io.ReadCloser, fileInfo os.FileInfo) error {
	l := caddy.Log()
	destFile, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, fileInfo.Mode())
	if err != nil {
		return fmt.Errorf("unable to open destination file: %v", err)
	}
	defer destFile.Close()

	l.Info("downloading binary", zap.String("destination", path))

	_, err = io.Copy(destFile, *body)
	if err != nil {
		return fmt.Errorf("unable to download file: %v", err)
	}

	err = destFile.Sync()
	if err != nil {
		return fmt.Errorf("syncing downloaded file to device: %v", err)
	}

	return nil
}

const downloadPath = "https://caddyserver.com/api/download"

type pluginPackage struct {
	Version string
	Path    string
}

func (p pluginPackage) String() string {
	if p.Version == "" {
		return p.Path
	}
	return p.Path + "@" + p.Version
}
