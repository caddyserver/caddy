package caddycmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"reflect"
	"runtime/debug"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

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
		iface := interface{}(modInfo.New())
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
	cmd := exec.Command(path, "list-modules", "--versions")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("download succeeded, but unable to execute: %v", err)
	}
	return nil
}

func showVersion(path string) error {
	cmd := exec.Command(path, "version")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("download succeeded, but unable to execute: %v", err)
	}
	return nil
}

func downloadBuild(qs url.Values) (*http.Response, error) {
	l := caddy.Log()
	l.Info("requesting build",
		zap.String("os", qs.Get("os")),
		zap.String("arch", qs.Get("arch")),
		zap.Strings("packages", qs["p"]))
	resp, err := http.Get(fmt.Sprintf("%s?%s", DownloadPath, qs.Encode()))
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

func getPluginPackages(modules []moduleInfo) (map[string]struct{}, error) {
	pluginPkgs := make(map[string]struct{})
	for _, mod := range modules {
		if mod.goModule.Replace != nil {
			return nil, fmt.Errorf("cannot auto-upgrade when Go module has been replaced: %s => %s",
				mod.goModule.Path, mod.goModule.Replace.Path)
		}
		pluginPkgs[mod.goModule.Path] = struct{}{}
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
