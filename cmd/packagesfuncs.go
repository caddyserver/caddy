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

	return module, version, err
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
		if _, ok := pluginPkgs[module]; ok && (version == "" || pluginPkgs[module].Version == version) {
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

	// get current version before upgrading
	currentVersion, _, err := caddy.Version()
	if err == nil {
		l.Info("current version", zap.String("version", currentVersion))
	}

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

	// download to a temporary file first to check the version
	downloadExecPath := thisExecPath + ".download"
	l.Info("download acquired; writing to temporary file",
		zap.String("download_path", downloadExecPath))
	err = writeCaddyBinary(downloadExecPath, &resp.Body, thisExecStat)
	if err != nil {
		return caddy.ExitCodeFailedStartup, err
	}

	// check version of the downloaded binary
	downloadVersion, err := getBinaryVersion(downloadExecPath)
	if err != nil {
		// if we can't get the version, clean up and proceed anyway
		// (version check is a safety feature, not a strict requirement)
		l.Warn("unable to check downloaded binary version; proceeding anyway",
			zap.Error(err))
	} else {
		l.Info("downloaded version", zap.String("version", downloadVersion))
		
		// compare versions
		allowDowngrade := fl.Bool("allow-downgrade")
		if !allowDowngrade && currentVersion != "" {
			cmp := compareVersions(currentVersion, downloadVersion)
			if cmp > 0 {
				// current version is newer than downloaded version - this would be a downgrade
				// clean up the downloaded file
				if err2 := removeCaddyBinary(downloadExecPath); err2 != nil {
					l.Error("unable to clean up downloaded binary",
						zap.String("download_path", downloadExecPath),
						zap.Error(err2))
				}
				return caddy.ExitCodeFailedStartup, fmt.Errorf(
					"downloaded version (%s) is older than current version (%s); "+
						"this would be a downgrade. Use --allow-downgrade to proceed anyway",
					downloadVersion, currentVersion)
			}
			if cmp == 0 {
				// same version - no upgrade needed
				if err2 := removeCaddyBinary(downloadExecPath); err2 != nil {
					l.Error("unable to clean up downloaded binary",
						zap.String("download_path", downloadExecPath),
						zap.Error(err2))
				}
				l.Info("downloaded version is the same as current version; no upgrade needed",
					zap.String("version", downloadVersion))
				fmt.Printf("Current version is already %s; no upgrade needed.\n", currentVersion)
				return caddy.ExitCodeSuccess, nil
			}
		}
	}

	// back up the current binary, in case something goes wrong we can replace it
	backupExecPath := thisExecPath + ".tmp"
	l.Info("version check passed; backing up current executable",
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

	// move the downloaded file to the final location
	err = os.Rename(downloadExecPath, thisExecPath)
	if err != nil {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("moving downloaded binary: %v", err)
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

// getBinaryVersion runs the binary with 'version' command and returns the simple version string.
func getBinaryVersion(path string) (string, error) {
	cmd := exec.Command(path, "version")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("unable to get version from binary: %v", err)
	}
	// the output is the full version string, but we want just the simple version
	// typically the first line or the first word before any whitespace
	fullVersion := strings.TrimSpace(string(output))
	// extract simple version - it's typically the first part of the output
	// format can be: "v2.4.0" or "v2.4.0 h1:..." or "v2.4.0\n..."
	parts := strings.Fields(fullVersion)
	if len(parts) == 0 {
		return "", fmt.Errorf("empty version output")
	}
	simpleVersion := parts[0]
	// if there are multiple lines, the first line is usually the simple version
	if lines := strings.Split(fullVersion, "\n"); len(lines) > 0 && lines[0] != "" {
		simpleVersion = strings.TrimSpace(lines[0])
		// take the first word of the first line
		if parts := strings.Fields(simpleVersion); len(parts) > 0 {
			simpleVersion = parts[0]
		}
	}
	return simpleVersion, nil
}

// compareVersions compares two version strings and returns:
// -1 if v1 < v2 (v1 is older)
// 0 if v1 == v2
// 1 if v1 > v2 (v1 is newer)
//
// It handles:
// - Semantic versions (v2.4.0, 2.4.0)
// - Git hash + date versions (abcd1234-20210309)
// - Unknown versions (returns 0 for comparison)
func compareVersions(v1, v2 string) int {
	// handle unknown versions
	if v1 == "unknown" || v1 == "(devel)" || v1 == "" {
		if v2 == "unknown" || v2 == "(devel)" || v2 == "" {
			return 0
		}
		// unknown is considered older than any known version
		return -1
	}
	if v2 == "unknown" || v2 == "(devel)" || v2 == "" {
		return 1
	}

	// check if versions are git hash + date format (e.g., "abcd1234-20210309")
	// this format is: 8-char hex hash + "-" + YYYYMMDD
	if isGitHashVersion(v1) && isGitHashVersion(v2) {
		return compareGitHashVersions(v1, v2)
	}

	// check if versions are semver format
	// normalize versions to have "v" prefix for semver comparison
	v1Norm := normalizeSemver(v1)
	v2Norm := normalizeSemver(v2)

	// if both look like semver, compare using semver logic
	if looksLikeSemver(v1Norm) && looksLikeSemver(v2Norm) {
		return compareSemver(v1Norm, v2Norm)
	}

	// if one is git hash and other is semver, we can't reliably compare
	// treat semver as newer than git hash (released versions are more stable)
	if isGitHashVersion(v1) && looksLikeSemver(v2Norm) {
		return -1 // git hash version is older than released semver version
	}
	if looksLikeSemver(v1Norm) && isGitHashVersion(v2) {
		return 1 // released semver version is newer than git hash version
	}

	// fallback: string comparison
	if v1 < v2 {
		return -1
	}
	if v1 > v2 {
		return 1
	}
	return 0
}

// isGitHashVersion checks if a version string is in git hash + date format.
// Format: 8-char hex hash + "-" + YYYYMMDD (e.g., "abcd1234-20210309")
func isGitHashVersion(v string) bool {
	// check if it matches the pattern: 8 hex chars + "-" + 8 digit date
	if len(v) < 18 {
		return false
	}
	// format is: hash(8) + "-" + date(8)
	parts := strings.Split(v, "-")
	if len(parts) != 2 {
		return false
	}
	hash := parts[0]
	date := parts[1]
	// hash should be 8 hex characters
	if len(hash) != 8 {
		return false
	}
	for _, c := range hash {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	// date should be YYYYMMDD (8 digits)
	if len(date) != 8 {
		return false
	}
	for _, c := range date {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// compareGitHashVersions compares two git hash + date versions.
// It compares the dates embedded in the versions.
func compareGitHashVersions(v1, v2 string) int {
	// extract dates from versions
	date1 := extractDateFromGitHash(v1)
	date2 := extractDateFromGitHash(v2)
	
	if date1 < date2 {
		return -1
	}
	if date1 > date2 {
		return 1
	}
	// same date, compare hashes (though unlikely to be meaningful)
	hash1 := extractHashFromGitHash(v1)
	hash2 := extractHashFromGitHash(v2)
	if hash1 < hash2 {
		return -1
	}
	if hash1 > hash2 {
		return 1
	}
	return 0
}

// extractDateFromGitHash extracts the date portion from a git hash version.
func extractDateFromGitHash(v string) string {
	parts := strings.Split(v, "-")
	if len(parts) == 2 {
		return parts[1]
	}
	return ""
}

// extractHashFromGitHash extracts the hash portion from a git hash version.
func extractHashFromGitHash(v string) string {
	parts := strings.Split(v, "-")
	if len(parts) == 2 {
		return parts[0]
	}
	return ""
}

// normalizeSemver ensures the version has a "v" prefix for semver comparison.
func normalizeSemver(v string) string {
	if v == "" {
		return ""
	}
	if !strings.HasPrefix(v, "v") {
		return "v" + v
	}
	return v
}

// looksLikeSemver checks if a version string looks like a semantic version.
func looksLikeSemver(v string) bool {
	if v == "" {
		return false
	}
	// must start with "v" followed by a digit
	if !strings.HasPrefix(v, "v") {
		return false
	}
	// check if it has at least vX.Y format
	rest := v[1:]
	parts := strings.Split(rest, ".")
	if len(parts) < 2 {
		return false
	}
	// each part before any pre-release suffix should be numeric
	for i, part := range parts {
		// handle pre-release suffix on last part (e.g., v2.4.0-beta.1)
		if i == len(parts)-1 {
			// split on "-" or "+" for pre-release/build metadata
			mainPart := part
			if idx := strings.Index(part, "-"); idx > 0 {
				mainPart = part[:idx]
			}
			if idx := strings.Index(part, "+"); idx > 0 {
				mainPart = part[:idx]
			}
			for _, c := range mainPart {
				if c < '0' || c > '9' {
					return false
				}
			}
		} else {
			for _, c := range part {
				if c < '0' || c > '9' {
					return false
				}
			}
		}
	}
	return true
}

// compareSemver compares two semantic version strings.
// Returns -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2.
func compareSemver(v1, v2 string) int {
	// parse major, minor, patch, and pre-release
	p1 := parseSemverParts(v1)
	p2 := parseSemverParts(v2)

	// compare major
	if p1.major < p2.major {
		return -1
	}
	if p1.major > p2.major {
		return 1
	}

	// compare minor
	if p1.minor < p2.minor {
		return -1
	}
	if p1.minor > p2.minor {
		return 1
	}

	// compare patch
	if p1.patch < p2.patch {
		return -1
	}
	if p1.patch > p2.patch {
		return 1
	}

	// compare pre-release
	// versions without pre-release are greater than those with pre-release
	// (e.g., v2.4.0 > v2.4.0-beta.1)
	if p1.prerelease == "" && p2.prerelease != "" {
		return 1
	}
	if p1.prerelease != "" && p2.prerelease == "" {
		return -1
	}
	if p1.prerelease < p2.prerelease {
		return -1
	}
	if p1.prerelease > p2.prerelease {
		return 1
	}

	return 0
}

// semverParts holds parsed semantic version components.
type semverParts struct {
	major      int
	minor      int
	patch      int
	prerelease string
}

// parseSemverParts parses a semantic version string into its components.
func parseSemverParts(v string) semverParts {
	result := semverParts{}
	
	// remove "v" prefix if present
	if strings.HasPrefix(v, "v") {
		v = v[1:]
	}

	// split on "+" for build metadata (ignore it)
	if idx := strings.Index(v, "+"); idx > 0 {
		v = v[:idx]
	}

	// split on "-" for pre-release
	var prerelease string
	if idx := strings.Index(v, "-"); idx > 0 {
		prerelease = v[idx+1:]
		v = v[:idx]
	}

	// split on "." for major.minor.patch
	parts := strings.Split(v, ".")
	
	if len(parts) >= 1 {
		result.major = parseInt(parts[0])
	}
	if len(parts) >= 2 {
		result.minor = parseInt(parts[1])
	}
	if len(parts) >= 3 {
		result.patch = parseInt(parts[2])
	}
	result.prerelease = prerelease

	return result
}

// parseInt parses a string to int, returning 0 on error.
func parseInt(s string) int {
	result := 0
	for _, c := range s {
		if c >= '0' && c <= '9' {
			result = result*10 + int(c-'0')
		} else {
			break
		}
	}
	return result
}

func getModules() (standard, nonstandard, unknown []moduleInfo, err error) {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		err = fmt.Errorf("no build info")
		return standard, nonstandard, unknown, err
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
	return standard, nonstandard, unknown, err
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