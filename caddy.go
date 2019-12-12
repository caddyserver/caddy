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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"path"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mholt/certmagic"
)

// Config is the top (or beginning) of the Caddy configuration structure.
// Caddy config is expressed natively as a JSON document. If you prefer
// not to work with JSON directly, there are [many config adapters](/docs/config-adapters)
// available that can convert various inputs into Caddy JSON.
//
// Many parts of this config are extensible through the use of Caddy modules.
// Fields which have a json.RawMessage type and which appear as dots (•••) in
// the online docs can be fulfilled by modules in a certain module
// namespace. The docs show which modules can be used in a given place.
//
// Whenever a module is used, its name must be given either inline as part of
// the module, or as the key to the module's value. The docs will make it clear
// which to use.
//
// Generally, all config settings are optional, as it is Caddy convention to
// have good, documented default values. If a parameter is required, the docs
// should say so.
//
// Go programs which are directly building a Config struct value should take
// care to populate the JSON-encodable fields of the struct (i.e. the fields
// with `json` struct tags) if employing the module lifecycle (e.g. Provision
// method calls).
type Config struct {
	Admin   *AdminConfig `json:"admin,omitempty"`
	Logging *Logging     `json:"logging,omitempty"`

	// StorageRaw is a storage module that defines how/where Caddy
	// stores assets (such as TLS certificates). By default, this is
	// the local file system (`caddy.storage.file_system` module).
	// If the `XDG_DATA_HOME` environment variable is set, then
	// `$XDG_DATA_HOME/caddy` is the default folder. Otherwise,
	// `$HOME/.local/share/caddy` is the default folder.
	StorageRaw json.RawMessage `json:"storage,omitempty" caddy:"namespace=caddy.storage inline_key=module"`

	// AppsRaw are the apps that Caddy will load and run. The
	// app module name is the key, and the app's config is the
	// associated value.
	AppsRaw ModuleMap `json:"apps,omitempty" caddy:"namespace="`

	apps    map[string]App
	storage certmagic.Storage

	cancelFunc context.CancelFunc
}

// App is a thing that Caddy runs.
type App interface {
	Start() error
	Stop() error
}

// Run runs the given config, replacing any existing config.
func Run(cfg *Config) error {
	cfgJSON, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	return Load(cfgJSON, true)
}

// Load loads the given config JSON and runs it only
// if it is different from the current config or
// forceReload is true.
func Load(cfgJSON []byte, forceReload bool) error {
	return changeConfig(http.MethodPost, "/"+rawConfigKey, cfgJSON, forceReload)
}

// changeConfig changes the current config (rawCfg) according to the
// method, traversed via the given path, and uses the given input as
// the new value (if applicable; i.e. "DELETE" doesn't have an input).
// If the resulting config is the same as the previous, no reload will
// occur unless forceReload is true. This function is safe for
// concurrent use.
func changeConfig(method, path string, input []byte, forceReload bool) error {
	switch method {
	case http.MethodGet,
		http.MethodHead,
		http.MethodOptions,
		http.MethodConnect,
		http.MethodTrace:
		return fmt.Errorf("method not allowed")
	}

	currentCfgMu.Lock()
	defer currentCfgMu.Unlock()

	err := unsyncedConfigAccess(method, path, input, nil)
	if err != nil {
		return err
	}

	// the mutation is complete, so encode the entire config as JSON
	newCfg, err := json.Marshal(rawCfg[rawConfigKey])
	if err != nil {
		return APIError{
			Code: http.StatusBadRequest,
			Err:  fmt.Errorf("encoding new config: %v", err),
		}
	}

	// if nothing changed, no need to do a whole reload unless the client forces it
	if !forceReload && bytes.Equal(rawCfgJSON, newCfg) {
		Log().Named("admin.api.change_config").Info("config is unchanged")
		return nil
	}

	// find any IDs in this config and index them
	idx := make(map[string]string)
	err = indexConfigObjects(rawCfg[rawConfigKey], "/"+rawConfigKey, idx)
	if err != nil {
		return APIError{
			Code: http.StatusInternalServerError,
			Err:  fmt.Errorf("indexing config: %v", err),
		}
	}

	// remove any @id fields from the JSON, which would cause
	// loading to break since the field wouldn't be recognized
	// (an alternate way to do this would be to delete them from
	// rawCfg as they are indexed, then iterate the index we made
	// and add them back after encoding as JSON)
	newCfg = RemoveMetaFields(newCfg)

	// load this new config; if it fails, we need to revert to
	// our old representation of caddy's actual config
	err = unsyncedDecodeAndRun(newCfg)
	if err != nil {
		if len(rawCfgJSON) > 0 {
			// restore old config state to keep it consistent
			// with what caddy is still running; we need to
			// unmarshal it again because it's likely that
			// pointers deep in our rawCfg map were modified
			var oldCfg interface{}
			err2 := json.Unmarshal(rawCfgJSON, &oldCfg)
			if err2 != nil {
				err = fmt.Errorf("%v; additionally, restoring old config: %v", err, err2)
			}
			rawCfg[rawConfigKey] = oldCfg
		}

		return fmt.Errorf("loading new config: %v", err)
	}

	// success, so update our stored copy of the encoded
	// config to keep it consistent with what caddy is now
	// running (storing an encoded copy is not strictly
	// necessary, but avoids an extra json.Marshal for
	// each config change)
	rawCfgJSON = newCfg
	rawCfgIndex = idx

	return nil
}

// readConfig traverses the current config to path
// and writes its JSON encoding to out.
func readConfig(path string, out io.Writer) error {
	currentCfgMu.RLock()
	defer currentCfgMu.RUnlock()
	return unsyncedConfigAccess(http.MethodGet, path, nil, out)
}

// indexConfigObjects recurisvely searches ptr for object fields named
// "@id" and maps that ID value to the full configPath in the index.
// This function is NOT safe for concurrent access; obtain a write lock
// on currentCfgMu.
func indexConfigObjects(ptr interface{}, configPath string, index map[string]string) error {
	switch val := ptr.(type) {
	case map[string]interface{}:
		for k, v := range val {
			if k == idKey {
				switch idVal := v.(type) {
				case string:
					index[idVal] = configPath
				case float64: // all JSON numbers decode as float64
					index[fmt.Sprintf("%v", idVal)] = configPath
				default:
					return fmt.Errorf("%s: %s field must be a string or number", configPath, idKey)
				}
				continue
			}
			// traverse this object property recursively
			err := indexConfigObjects(val[k], path.Join(configPath, k), index)
			if err != nil {
				return err
			}
		}
	case []interface{}:
		// traverse each element of the array recursively
		for i := range val {
			err := indexConfigObjects(val[i], path.Join(configPath, strconv.Itoa(i)), index)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// unsyncedDecodeAndRun decodes cfgJSON and runs
// it as the new config, replacing any other
// current config. It does not update the raw
// config state, as this is a lower-level function;
// most callers will want to use Load instead.
// A write lock on currentCfgMu is required!
func unsyncedDecodeAndRun(cfgJSON []byte) error {
	var newCfg *Config
	err := strictUnmarshalJSON(cfgJSON, &newCfg)
	if err != nil {
		return err
	}

	// run the new config and start all its apps
	err = run(newCfg, true)
	if err != nil {
		return err
	}

	// swap old config with the new one
	oldCfg := currentCfg
	currentCfg = newCfg

	// Stop, Cleanup each old app
	unsyncedStop(oldCfg)

	return nil
}

// run runs newCfg and starts all its apps if
// start is true. If any errors happen, cleanup
// is performed if any modules were provisioned;
// apps that were started already will be stopped,
// so this function should not leak resources if
// an error is returned. However, if no error is
// returned and start == false, you should cancel
// the config if you are not going to start it,
// so that each provisioned module will be
// cleaned up.
//
// This is a low-level function; most callers
// will want to use Run instead, which also
// updates the config's raw state.
func run(newCfg *Config, start bool) error {
	// because we will need to roll back any state
	// modifications if this function errors, we
	// keep a single error value and scope all
	// sub-operations to their own functions to
	// ensure this error value does not get
	// overridden or missed when it should have
	// been set by a short assignment
	var err error

	// start the admin endpoint (and stop any prior one)
	if start {
		err = replaceAdmin(newCfg)
		if err != nil {
			return fmt.Errorf("starting caddy administration endpoint: %v", err)
		}
	}

	if newCfg == nil {
		return nil
	}

	// prepare the new config for use
	newCfg.apps = make(map[string]App)

	// create a context within which to load
	// modules - essentially our new config's
	// execution environment; be sure that
	// cleanup occurs when we return if there
	// was an error; if no error, it will get
	// cleaned up on next config cycle
	ctx, cancel := NewContext(Context{Context: context.Background(), cfg: newCfg})
	defer func() {
		if err != nil {
			// if there were any errors during startup,
			// we should cancel the new context we created
			// since the associated config won't be used;
			// this will cause all modules that were newly
			// provisioned to clean themselves up
			cancel()

			// also undo any other state changes we made
			if currentCfg != nil {
				certmagic.Default.Storage = currentCfg.storage
			}
		}
	}()
	newCfg.cancelFunc = cancel // clean up later

	// set up logging before anything bad happens
	if newCfg.Logging == nil {
		newCfg.Logging = new(Logging)
	}
	err = newCfg.Logging.openLogs(ctx)
	if err != nil {
		return err
	}

	// set up global storage and make it CertMagic's default storage, too
	err = func() error {
		if newCfg.StorageRaw != nil {
			val, err := ctx.LoadModule(newCfg, "StorageRaw")
			if err != nil {
				return fmt.Errorf("loading storage module: %v", err)
			}
			stor, err := val.(StorageConverter).CertMagicStorage()
			if err != nil {
				return fmt.Errorf("creating storage value: %v", err)
			}
			newCfg.storage = stor
		}

		if newCfg.storage == nil {
			newCfg.storage = &certmagic.FileStorage{Path: dataDir()}
		}
		certmagic.Default.Storage = newCfg.storage

		return nil
	}()
	if err != nil {
		return err
	}

	// Load, Provision, Validate each app and their submodules
	err = func() error {
		appsIface, err := ctx.LoadModule(newCfg, "AppsRaw")
		if err != nil {
			return fmt.Errorf("loading app modules: %v", err)
		}
		for appName, appIface := range appsIface.(map[string]interface{}) {
			newCfg.apps[appName] = appIface.(App)
		}
		return nil
	}()
	if err != nil {
		return err
	}

	if !start {
		return nil
	}

	// Start
	return func() error {
		var started []string
		for name, a := range newCfg.apps {
			err := a.Start()
			if err != nil {
				// an app failed to start, so we need to stop
				// all other apps that were already started
				for _, otherAppName := range started {
					err2 := newCfg.apps[otherAppName].Stop()
					if err2 != nil {
						err = fmt.Errorf("%v; additionally, aborting app %s: %v",
							err, otherAppName, err2)
					}
				}
				return fmt.Errorf("%s app module: start: %v", name, err)
			}
			started = append(started, name)
		}
		return nil
	}()
}

// Stop stops running the current configuration.
// It is the antithesis of Run(). This function
// will log any errors that occur during the
// stopping of individual apps and continue to
// stop the others. Stop should only be called
// if not replacing with a new config.
func Stop() error {
	currentCfgMu.Lock()
	defer currentCfgMu.Unlock()
	unsyncedStop(currentCfg)
	currentCfg = nil
	rawCfgJSON = nil
	rawCfgIndex = nil
	rawCfg[rawConfigKey] = nil
	return nil
}

// unsyncedStop stops cfg from running, but has
// no locking around cfg. It is a no-op if cfg is
// nil. If any app returns an error when stopping,
// it is logged and the function continues stopping
// the next app. This function assumes all apps in
// cfg were successfully started first.
func unsyncedStop(cfg *Config) {
	if cfg == nil {
		return
	}

	// stop each app
	for name, a := range cfg.apps {
		err := a.Stop()
		if err != nil {
			log.Printf("[ERROR] stop %s: %v", name, err)
		}
	}

	// clean up all modules
	cfg.cancelFunc()
}

// stopAndCleanup calls stop and cleans up anything
// else that is expedient. This should only be used
// when stopping and not replacing with a new config.
func stopAndCleanup() error {
	if err := Stop(); err != nil {
		return err
	}
	certmagic.CleanUpOwnLocks()
	return nil
}

// Validate loads, provisions, and validates
// cfg, but does not start running it.
func Validate(cfg *Config) error {
	err := run(cfg, false)
	if err == nil {
		cfg.cancelFunc() // call Cleanup on all modules
	}
	return err
}

// Duration can be an integer or a string. An integer is
// interpreted as nanoseconds. If a string, it is a Go
// time.Duration value such as `300ms`, `1.5h`, or `2h45m`;
// valid units are `ns`, `us`/`µs`, `ms`, `s`, `m`, and `h`.
type Duration time.Duration

// UnmarshalJSON satisfies json.Unmarshaler.
func (d *Duration) UnmarshalJSON(b []byte) error {
	if len(b) == 0 {
		return io.EOF
	}
	var dur time.Duration
	var err error
	if b[0] == byte('"') && b[len(b)-1] == byte('"') {
		dur, err = time.ParseDuration(strings.Trim(string(b), `"`))
	} else {
		err = json.Unmarshal(b, &dur)
	}
	*d = Duration(dur)
	return err
}

// GoModule returns the build info of this Caddy
// build from debug.BuildInfo (requires Go modules).
// If no version information is available, a non-nil
// value will still be returned, but with an
// unknown version.
func GoModule() *debug.Module {
	var mod debug.Module
	return goModule(&mod)
}

// goModule holds the actual implementation of GoModule.
// Allocating debug.Module in GoModule() and passing a
// reference to goModule enables mid-stack inlining.
func goModule(mod *debug.Module) *debug.Module {
	mod.Version = "unknown"
	bi, ok := debug.ReadBuildInfo()
	if ok {
		mod.Path = bi.Main.Path
		// The recommended way to build Caddy involves
		// creating a separate main module, which
		// TODO: track related Go issue: https://github.com/golang/go/issues/29228
		// once that issue is fixed, we should just be able to use bi.Main... hopefully.
		for _, dep := range bi.Deps {
			if dep.Path == "github.com/caddyserver/caddy/v2" {
				return dep
			}
		}
		return &bi.Main
	}
	return mod
}

// CtxKey is a value type for use with context.WithValue.
type CtxKey string

// This group of variables pertains to the current configuration.
var (
	// currentCfgMu protects everything in this var block.
	currentCfgMu sync.RWMutex

	// currentCfg is the currently-running configuration.
	currentCfg *Config

	// rawCfg is the current, generic-decoded configuration;
	// we initialize it as a map with one field ("config")
	// to maintain parity with the API endpoint and to avoid
	// the special case of having to access/mutate the variable
	// directly without traversing into it.
	rawCfg = map[string]interface{}{
		rawConfigKey: nil,
	}

	// rawCfgJSON is the JSON-encoded form of rawCfg. Keeping
	// this around avoids an extra Marshal call during changes.
	rawCfgJSON []byte

	// rawCfgIndex is the map of user-assigned ID to expanded
	// path, for converting /id/ paths to /config/ paths.
	rawCfgIndex map[string]string
)
