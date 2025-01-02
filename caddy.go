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
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2/internal/filesystems"
	"github.com/caddyserver/caddy/v2/notify"
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
	// stores assets (such as TLS certificates). The default storage
	// module is `caddy.storage.file_system` (the local file system),
	// and the default path
	// [depends on the OS and environment](/docs/conventions#data-directory).
	StorageRaw json.RawMessage `json:"storage,omitempty" caddy:"namespace=caddy.storage inline_key=module"`

	// AppsRaw are the apps that Caddy will load and run. The
	// app module name is the key, and the app's config is the
	// associated value.
	AppsRaw ModuleMap `json:"apps,omitempty" caddy:"namespace="`

	apps    map[string]App
	storage certmagic.Storage

	cancelFunc context.CancelFunc

	// filesystems is a dict of filesystems that will later be loaded from and added to.
	filesystems FileSystems
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
	if err := notify.Reloading(); err != nil {
		Log().Error("unable to notify service manager of reloading state", zap.Error(err))
	}

	// after reload, notify system of success or, if
	// failure, update with status (error message)
	var err error
	defer func() {
		if err != nil {
			if notifyErr := notify.Error(err, 0); notifyErr != nil {
				Log().Error("unable to notify to service manager of reload error",
					zap.Error(notifyErr),
					zap.String("reload_err", err.Error()))
			}
			return
		}
		if err := notify.Ready(); err != nil {
			Log().Error("unable to notify to service manager of ready state", zap.Error(err))
		}
	}()

	err = changeConfig(http.MethodPost, "/"+rawConfigKey, cfgJSON, "", forceReload)
	if errors.Is(err, errSameConfig) {
		err = nil // not really an error
	}

	return err
}

// changeConfig changes the current config (rawCfg) according to the
// method, traversed via the given path, and uses the given input as
// the new value (if applicable; i.e. "DELETE" doesn't have an input).
// If the resulting config is the same as the previous, no reload will
// occur unless forceReload is true. If the config is unchanged and not
// forcefully reloaded, then errConfigUnchanged This function is safe for
// concurrent use.
// The ifMatchHeader can optionally be given a string of the format:
//
//	"<path> <hash>"
//
// where <path> is the absolute path in the config and <hash> is the expected hash of
// the config at that path. If the hash in the ifMatchHeader doesn't match
// the hash of the config, then an APIError with status 412 will be returned.
func changeConfig(method, path string, input []byte, ifMatchHeader string, forceReload bool) error {
	switch method {
	case http.MethodGet,
		http.MethodHead,
		http.MethodOptions,
		http.MethodConnect,
		http.MethodTrace:
		return fmt.Errorf("method not allowed")
	}

	rawCfgMu.Lock()
	defer rawCfgMu.Unlock()

	if ifMatchHeader != "" {
		// expect the first and last character to be quotes
		if len(ifMatchHeader) < 2 || ifMatchHeader[0] != '"' || ifMatchHeader[len(ifMatchHeader)-1] != '"' {
			return APIError{
				HTTPStatus: http.StatusBadRequest,
				Err:        fmt.Errorf("malformed If-Match header; expect quoted string"),
			}
		}

		// read out the parts
		parts := strings.Fields(ifMatchHeader[1 : len(ifMatchHeader)-1])
		if len(parts) != 2 {
			return APIError{
				HTTPStatus: http.StatusBadRequest,
				Err:        fmt.Errorf("malformed If-Match header; expect format \"<path> <hash>\""),
			}
		}

		// get the current hash of the config
		// at the given path
		hash := etagHasher()
		err := unsyncedConfigAccess(http.MethodGet, parts[0], nil, hash)
		if err != nil {
			return err
		}

		if hex.EncodeToString(hash.Sum(nil)) != parts[1] {
			return APIError{
				HTTPStatus: http.StatusPreconditionFailed,
				Err:        fmt.Errorf("If-Match header did not match current config hash"),
			}
		}
	}

	err := unsyncedConfigAccess(method, path, input, nil)
	if err != nil {
		return err
	}

	// the mutation is complete, so encode the entire config as JSON
	newCfg, err := json.Marshal(rawCfg[rawConfigKey])
	if err != nil {
		return APIError{
			HTTPStatus: http.StatusBadRequest,
			Err:        fmt.Errorf("encoding new config: %v", err),
		}
	}

	// if nothing changed, no need to do a whole reload unless the client forces it
	if !forceReload && bytes.Equal(rawCfgJSON, newCfg) {
		Log().Info("config is unchanged")
		return errSameConfig
	}

	// find any IDs in this config and index them
	idx := make(map[string]string)
	err = indexConfigObjects(rawCfg[rawConfigKey], "/"+rawConfigKey, idx)
	if err != nil {
		return APIError{
			HTTPStatus: http.StatusInternalServerError,
			Err:        fmt.Errorf("indexing config: %v", err),
		}
	}

	// load this new config; if it fails, we need to revert to
	// our old representation of caddy's actual config
	err = unsyncedDecodeAndRun(newCfg, true)
	if err != nil {
		if len(rawCfgJSON) > 0 {
			// restore old config state to keep it consistent
			// with what caddy is still running; we need to
			// unmarshal it again because it's likely that
			// pointers deep in our rawCfg map were modified
			var oldCfg any
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
	rawCfgMu.RLock()
	defer rawCfgMu.RUnlock()
	return unsyncedConfigAccess(http.MethodGet, path, nil, out)
}

// indexConfigObjects recursively searches ptr for object fields named
// "@id" and maps that ID value to the full configPath in the index.
// This function is NOT safe for concurrent access; obtain a write lock
// on currentCtxMu.
func indexConfigObjects(ptr any, configPath string, index map[string]string) error {
	switch val := ptr.(type) {
	case map[string]any:
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
	case []any:
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

// unsyncedDecodeAndRun removes any meta fields (like @id tags)
// from cfgJSON, decodes the result into a *Config, and runs
// it as the new config, replacing any other current config.
// It does NOT update the raw config state, as this is a
// lower-level function; most callers will want to use Load
// instead. A write lock on rawCfgMu is required! If
// allowPersist is false, it will not be persisted to disk,
// even if it is configured to.
func unsyncedDecodeAndRun(cfgJSON []byte, allowPersist bool) error {
	// remove any @id fields from the JSON, which would cause
	// loading to break since the field wouldn't be recognized
	strippedCfgJSON := RemoveMetaFields(cfgJSON)

	var newCfg *Config
	err := StrictUnmarshalJSON(strippedCfgJSON, &newCfg)
	if err != nil {
		return err
	}

	// prevent recursive config loads; that is a user error, and
	// although frequent config loads should be safe, we cannot
	// guarantee that in the presence of third party plugins, nor
	// do we want this error to go unnoticed (we assume it was a
	// pulled config if we're not allowed to persist it)
	if !allowPersist &&
		newCfg != nil &&
		newCfg.Admin != nil &&
		newCfg.Admin.Config != nil &&
		newCfg.Admin.Config.LoadRaw != nil &&
		newCfg.Admin.Config.LoadDelay <= 0 {
		return fmt.Errorf("recursive config loading detected: pulled configs cannot pull other configs without positive load_delay")
	}

	// run the new config and start all its apps
	ctx, err := run(newCfg, true)
	if err != nil {
		return err
	}

	// swap old context (including its config) with the new one
	currentCtxMu.Lock()
	oldCtx := currentCtx
	currentCtx = ctx
	currentCtxMu.Unlock()

	// Stop, Cleanup each old app
	unsyncedStop(oldCtx)

	// autosave a non-nil config, if not disabled
	if allowPersist &&
		newCfg != nil &&
		(newCfg.Admin == nil ||
			newCfg.Admin.Config == nil ||
			newCfg.Admin.Config.Persist == nil ||
			*newCfg.Admin.Config.Persist) {
		dir := filepath.Dir(ConfigAutosavePath)
		err := os.MkdirAll(dir, 0o700)
		if err != nil {
			Log().Error("unable to create folder for config autosave",
				zap.String("dir", dir),
				zap.Error(err))
		} else {
			err := os.WriteFile(ConfigAutosavePath, cfgJSON, 0o600)
			if err == nil {
				Log().Info("autosaved config (load with --resume flag)", zap.String("file", ConfigAutosavePath))
			} else {
				Log().Error("unable to autosave config",
					zap.String("file", ConfigAutosavePath),
					zap.Error(err))
			}
		}
	}

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
func run(newCfg *Config, start bool) (Context, error) {
	ctx, err := provisionContext(newCfg, start)
	if err != nil {
		globalMetrics.configSuccess.Set(0)
		return ctx, err
	}

	if !start {
		return ctx, nil
	}

	// Provision any admin routers which may need to access
	// some of the other apps at runtime
	err = ctx.cfg.Admin.provisionAdminRouters(ctx)
	if err != nil {
		globalMetrics.configSuccess.Set(0)
		return ctx, err
	}

	// Start
	err = func() error {
		started := make([]string, 0, len(ctx.cfg.apps))
		for name, a := range ctx.cfg.apps {
			err := a.Start()
			if err != nil {
				// an app failed to start, so we need to stop
				// all other apps that were already started
				for _, otherAppName := range started {
					err2 := ctx.cfg.apps[otherAppName].Stop()
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
	if err != nil {
		globalMetrics.configSuccess.Set(0)
		return ctx, err
	}
	globalMetrics.configSuccess.Set(1)
	globalMetrics.configSuccessTime.SetToCurrentTime()
	// now that the user's config is running, finish setting up anything else,
	// such as remote admin endpoint, config loader, etc.
	return ctx, finishSettingUp(ctx, ctx.cfg)
}

// provisionContext creates a new context from the given configuration and provisions
// storage and apps.
// If `newCfg` is nil a new empty configuration will be created.
// If `replaceAdminServer` is true any currently active admin server will be replaced
// with a new admin server based on the provided configuration.
func provisionContext(newCfg *Config, replaceAdminServer bool) (Context, error) {
	// because we will need to roll back any state
	// modifications if this function errors, we
	// keep a single error value and scope all
	// sub-operations to their own functions to
	// ensure this error value does not get
	// overridden or missed when it should have
	// been set by a short assignment
	var err error

	if newCfg == nil {
		newCfg = new(Config)
	}

	// create a context within which to load
	// modules - essentially our new config's
	// execution environment; be sure that
	// cleanup occurs when we return if there
	// was an error; if no error, it will get
	// cleaned up on next config cycle
	ctx, cancel := NewContext(Context{Context: context.Background(), cfg: newCfg})
	defer func() {
		if err != nil {
			globalMetrics.configSuccess.Set(0)
			// if there were any errors during startup,
			// we should cancel the new context we created
			// since the associated config won't be used;
			// this will cause all modules that were newly
			// provisioned to clean themselves up
			cancel()

			// also undo any other state changes we made
			if currentCtx.cfg != nil {
				certmagic.Default.Storage = currentCtx.cfg.storage
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
		return ctx, err
	}

	// start the admin endpoint (and stop any prior one)
	if replaceAdminServer {
		err = replaceLocalAdminServer(newCfg, ctx)
		if err != nil {
			return ctx, fmt.Errorf("starting caddy administration endpoint: %v", err)
		}
	}

	// create the new filesystem map
	newCfg.filesystems = &filesystems.FilesystemMap{}

	// prepare the new config for use
	newCfg.apps = make(map[string]App)

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
			newCfg.storage = DefaultStorage
		}
		certmagic.Default.Storage = newCfg.storage

		return nil
	}()
	if err != nil {
		return ctx, err
	}

	// Load and Provision each app and their submodules
	err = func() error {
		for appName := range newCfg.AppsRaw {
			if _, err := ctx.App(appName); err != nil {
				return err
			}
		}
		return nil
	}()
	return ctx, err
}

// ProvisionContext creates a new context from the configuration and provisions storage
// and app modules.
// The function is intended for testing and advanced use cases only, typically `Run` should be
// use to ensure a fully functional caddy instance.
// EXPERIMENTAL: While this is public the interface and implementation details of this function may change.
func ProvisionContext(newCfg *Config) (Context, error) {
	return provisionContext(newCfg, false)
}

// finishSettingUp should be run after all apps have successfully started.
func finishSettingUp(ctx Context, cfg *Config) error {
	// establish this server's identity (only after apps are loaded
	// so that cert management of this endpoint doesn't prevent user's
	// servers from starting which likely also use HTTP/HTTPS ports;
	// but before remote management which may depend on these creds)
	err := manageIdentity(ctx, cfg)
	if err != nil {
		return fmt.Errorf("provisioning remote admin endpoint: %v", err)
	}

	// replace any remote admin endpoint
	err = replaceRemoteAdminServer(ctx, cfg)
	if err != nil {
		return fmt.Errorf("provisioning remote admin endpoint: %v", err)
	}

	// if dynamic config is requested, set that up and run it
	if cfg != nil && cfg.Admin != nil && cfg.Admin.Config != nil && cfg.Admin.Config.LoadRaw != nil {
		val, err := ctx.LoadModule(cfg.Admin.Config, "LoadRaw")
		if err != nil {
			return fmt.Errorf("loading config loader module: %s", err)
		}

		logger := Log().Named("config_loader").With(
			zap.String("module", val.(Module).CaddyModule().ID.Name()),
			zap.Int("load_delay", int(cfg.Admin.Config.LoadDelay)))

		runLoadedConfig := func(config []byte) error {
			logger.Info("applying dynamically-loaded config")
			err := changeConfig(http.MethodPost, "/"+rawConfigKey, config, "", false)
			if errors.Is(err, errSameConfig) {
				return err
			}
			if err != nil {
				logger.Error("failed to run dynamically-loaded config", zap.Error(err))
				return err
			}
			logger.Info("successfully applied dynamically-loaded config")
			return nil
		}

		if cfg.Admin.Config.LoadDelay > 0 {
			go func() {
				// the loop is here to iterate ONLY if there is an error, a no-op config load,
				// or an unchanged config; in which case we simply wait the delay and try again
				for {
					timer := time.NewTimer(time.Duration(cfg.Admin.Config.LoadDelay))
					select {
					case <-timer.C:
						loadedConfig, err := val.(ConfigLoader).LoadConfig(ctx)
						if err != nil {
							logger.Error("failed loading dynamic config; will retry", zap.Error(err))
							continue
						}
						if loadedConfig == nil {
							logger.Info("dynamically-loaded config was nil; will retry")
							continue
						}
						err = runLoadedConfig(loadedConfig)
						if errors.Is(err, errSameConfig) {
							logger.Info("dynamically-loaded config was unchanged; will retry")
							continue
						}
					case <-ctx.Done():
						if !timer.Stop() {
							<-timer.C
						}
						logger.Info("stopping dynamic config loading")
					}
					break
				}
			}()
		} else {
			// if no LoadDelay is provided, will load config synchronously
			loadedConfig, err := val.(ConfigLoader).LoadConfig(ctx)
			if err != nil {
				return fmt.Errorf("loading dynamic config from %T: %v", val, err)
			}
			// do this in a goroutine so current config can finish being loaded; otherwise deadlock
			go func() { _ = runLoadedConfig(loadedConfig) }()
		}
	}

	return nil
}

// ConfigLoader is a type that can load a Caddy config. If
// the return value is non-nil, it must be valid Caddy JSON;
// if nil or with non-nil error, it is considered to be a
// no-op load and may be retried later.
type ConfigLoader interface {
	LoadConfig(Context) ([]byte, error)
}

// Stop stops running the current configuration.
// It is the antithesis of Run(). This function
// will log any errors that occur during the
// stopping of individual apps and continue to
// stop the others. Stop should only be called
// if not replacing with a new config.
func Stop() error {
	currentCtxMu.RLock()
	ctx := currentCtx
	currentCtxMu.RUnlock()

	rawCfgMu.Lock()
	unsyncedStop(ctx)

	currentCtxMu.Lock()
	currentCtx = Context{}
	currentCtxMu.Unlock()

	rawCfgJSON = nil
	rawCfgIndex = nil
	rawCfg[rawConfigKey] = nil
	rawCfgMu.Unlock()

	return nil
}

// unsyncedStop stops ctx from running, but has
// no locking around ctx. It is a no-op if ctx has a
// nil cfg. If any app returns an error when stopping,
// it is logged and the function continues stopping
// the next app. This function assumes all apps in
// ctx were successfully started first.
//
// A lock on rawCfgMu is required, even though this
// function does not access rawCfg, that lock
// synchronizes the stop/start of apps.
func unsyncedStop(ctx Context) {
	if ctx.cfg == nil {
		return
	}

	// stop each app
	for name, a := range ctx.cfg.apps {
		err := a.Stop()
		if err != nil {
			log.Printf("[ERROR] stop %s: %v", name, err)
		}
	}

	// clean up all modules
	ctx.cfg.cancelFunc()
}

// Validate loads, provisions, and validates
// cfg, but does not start running it.
func Validate(cfg *Config) error {
	_, err := run(cfg, false)
	if err == nil {
		cfg.cancelFunc() // call Cleanup on all modules
	}
	return err
}

// exitProcess exits the process as gracefully as possible,
// but it always exits, even if there are errors doing so.
// It stops all apps, cleans up external locks, removes any
// PID file, and shuts down admin endpoint(s) in a goroutine.
// Errors are logged along the way, and an appropriate exit
// code is emitted.
func exitProcess(ctx context.Context, logger *zap.Logger) {
	// let the rest of the program know we're quitting; only do it once
	if !atomic.CompareAndSwapInt32(exiting, 0, 1) {
		return
	}

	// give the OS or service/process manager our 2 weeks' notice: we quit
	if err := notify.Stopping(); err != nil {
		Log().Error("unable to notify service manager of stopping state", zap.Error(err))
	}

	if logger == nil {
		logger = Log()
	}
	logger.Warn("exiting; byeee!! 👋")

	exitCode := ExitCodeSuccess
	lastContext := ActiveContext()

	// stop all apps
	if err := Stop(); err != nil {
		logger.Error("failed to stop apps", zap.Error(err))
		exitCode = ExitCodeFailedQuit
	}

	// clean up certmagic locks
	certmagic.CleanUpOwnLocks(ctx, logger)

	// remove pidfile
	if pidfile != "" {
		err := os.Remove(pidfile)
		if err != nil {
			logger.Error("cleaning up PID file:",
				zap.String("pidfile", pidfile),
				zap.Error(err))
			exitCode = ExitCodeFailedQuit
		}
	}

	// execute any process-exit callbacks
	for _, exitFunc := range lastContext.exitFuncs {
		exitFunc(ctx)
	}
	exitFuncsMu.Lock()
	for _, exitFunc := range exitFuncs {
		exitFunc(ctx)
	}
	exitFuncsMu.Unlock()

	// shut down admin endpoint(s) in goroutines so that
	// if this function was called from an admin handler,
	// it has a chance to return gracefully
	// use goroutine so that we can finish responding to API request
	go func() {
		defer func() {
			logger = logger.With(zap.Int("exit_code", exitCode))
			if exitCode == ExitCodeSuccess {
				logger.Info("shutdown complete")
			} else {
				logger.Error("unclean shutdown")
			}
			os.Exit(exitCode)
		}()

		if remoteAdminServer != nil {
			err := stopAdminServer(remoteAdminServer)
			if err != nil {
				exitCode = ExitCodeFailedQuit
				logger.Error("failed to stop remote admin server gracefully", zap.Error(err))
			}
		}
		if localAdminServer != nil {
			err := stopAdminServer(localAdminServer)
			if err != nil {
				exitCode = ExitCodeFailedQuit
				logger.Error("failed to stop local admin server gracefully", zap.Error(err))
			}
		}
	}()
}

var exiting = new(int32) // accessed atomically

// Exiting returns true if the process is exiting.
// EXPERIMENTAL API: subject to change or removal.
func Exiting() bool { return atomic.LoadInt32(exiting) == 1 }

// OnExit registers a callback to invoke during process exit.
// This registration is PROCESS-GLOBAL, meaning that each
// function should only be registered once forever, NOT once
// per config load (etc).
//
// EXPERIMENTAL API: subject to change or removal.
func OnExit(f func(context.Context)) {
	exitFuncsMu.Lock()
	exitFuncs = append(exitFuncs, f)
	exitFuncsMu.Unlock()
}

var (
	exitFuncs   []func(context.Context)
	exitFuncsMu sync.Mutex
)

// Duration can be an integer or a string. An integer is
// interpreted as nanoseconds. If a string, it is a Go
// time.Duration value such as `300ms`, `1.5h`, or `2h45m`;
// valid units are `ns`, `us`/`µs`, `ms`, `s`, `m`, `h`, and `d`.
type Duration time.Duration

// UnmarshalJSON satisfies json.Unmarshaler.
func (d *Duration) UnmarshalJSON(b []byte) error {
	if len(b) == 0 {
		return io.EOF
	}
	var dur time.Duration
	var err error
	if b[0] == byte('"') && b[len(b)-1] == byte('"') {
		dur, err = ParseDuration(strings.Trim(string(b), `"`))
	} else {
		err = json.Unmarshal(b, &dur)
	}
	*d = Duration(dur)
	return err
}

// ParseDuration parses a duration string, adding
// support for the "d" unit meaning number of days,
// where a day is assumed to be 24h. The maximum
// input string length is 1024.
func ParseDuration(s string) (time.Duration, error) {
	if len(s) > 1024 {
		return 0, fmt.Errorf("parsing duration: input string too long")
	}
	var inNumber bool
	var numStart int
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch == 'd' {
			daysStr := s[numStart:i]
			days, err := strconv.ParseFloat(daysStr, 64)
			if err != nil {
				return 0, err
			}
			hours := days * 24.0
			hoursStr := strconv.FormatFloat(hours, 'f', -1, 64)
			s = s[:numStart] + hoursStr + "h" + s[i+1:]
			i--
			continue
		}
		if !inNumber {
			numStart = i
		}
		inNumber = (ch >= '0' && ch <= '9') || ch == '.' || ch == '-' || ch == '+'
	}
	return time.ParseDuration(s)
}

// InstanceID returns the UUID for this instance, and generates one if it
// does not already exist. The UUID is stored in the local data directory,
// regardless of storage configuration, since each instance is intended to
// have its own unique ID.
func InstanceID() (uuid.UUID, error) {
	appDataDir := AppDataDir()
	uuidFilePath := filepath.Join(appDataDir, "instance.uuid")
	uuidFileBytes, err := os.ReadFile(uuidFilePath)
	if errors.Is(err, fs.ErrNotExist) {
		uuid, err := uuid.NewRandom()
		if err != nil {
			return uuid, err
		}
		err = os.MkdirAll(appDataDir, 0o700)
		if err != nil {
			return uuid, err
		}
		err = os.WriteFile(uuidFilePath, []byte(uuid.String()), 0o600)
		return uuid, err
	} else if err != nil {
		return [16]byte{}, err
	}
	return uuid.ParseBytes(uuidFileBytes)
}

// CustomVersion is an optional string that overrides Caddy's
// reported version. It can be helpful when downstream packagers
// need to manually set Caddy's version. If no other version
// information is available, the short form version (see
// Version()) will be set to CustomVersion, and the full version
// will include CustomVersion at the beginning.
//
// Set this variable during `go build` with `-ldflags`:
//
//	-ldflags '-X github.com/caddyserver/caddy/v2.CustomVersion=v2.6.2'
//
// for example.
var CustomVersion string

// Version returns the Caddy version in a simple/short form, and
// a full version string. The short form will not have spaces and
// is intended for User-Agent strings and similar, but may be
// omitting valuable information. Note that Caddy must be compiled
// in a special way to properly embed complete version information.
// First this function tries to get the version from the embedded
// build info provided by go.mod dependencies; then it tries to
// get info from embedded VCS information, which requires having
// built Caddy from a git repository. If no version is available,
// this function returns "(devel)" because Go uses that, but for
// the simple form we change it to "unknown". If still no version
// is available (e.g. no VCS repo), then it will use CustomVersion;
// CustomVersion is always prepended to the full version string.
//
// See relevant Go issues: https://github.com/golang/go/issues/29228
// and https://github.com/golang/go/issues/50603.
//
// This function is experimental and subject to change or removal.
func Version() (simple, full string) {
	// the currently-recommended way to build Caddy involves
	// building it as a dependency so we can extract version
	// information from go.mod tooling; once the upstream
	// Go issues are fixed, we should just be able to use
	// bi.Main... hopefully.
	var module *debug.Module
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		if CustomVersion != "" {
			full = CustomVersion
			simple = CustomVersion
			return
		}
		full = "unknown"
		simple = "unknown"
		return
	}
	// find the Caddy module in the dependency list
	for _, dep := range bi.Deps {
		if dep.Path == ImportPath {
			module = dep
			break
		}
	}
	if module != nil {
		simple, full = module.Version, module.Version
		if module.Sum != "" {
			full += " " + module.Sum
		}
		if module.Replace != nil {
			full += " => " + module.Replace.Path
			if module.Replace.Version != "" {
				simple = module.Replace.Version + "_custom"
				full += "@" + module.Replace.Version
			}
			if module.Replace.Sum != "" {
				full += " " + module.Replace.Sum
			}
		}
	}

	if full == "" {
		var vcsRevision string
		var vcsTime time.Time
		var vcsModified bool
		for _, setting := range bi.Settings {
			switch setting.Key {
			case "vcs.revision":
				vcsRevision = setting.Value
			case "vcs.time":
				vcsTime, _ = time.Parse(time.RFC3339, setting.Value)
			case "vcs.modified":
				vcsModified, _ = strconv.ParseBool(setting.Value)
			}
		}

		if vcsRevision != "" {
			var modified string
			if vcsModified {
				modified = "+modified"
			}
			full = fmt.Sprintf("%s%s (%s)", vcsRevision, modified, vcsTime.Format(time.RFC822))
			simple = vcsRevision

			// use short checksum for simple, if hex-only
			if _, err := hex.DecodeString(simple); err == nil {
				simple = simple[:8]
			}

			// append date to simple since it can be convenient
			// to know the commit date as part of the version
			if !vcsTime.IsZero() {
				simple += "-" + vcsTime.Format("20060102")
			}
		}
	}

	if full == "" {
		if CustomVersion != "" {
			full = CustomVersion
		} else {
			full = "unknown"
		}
	} else if CustomVersion != "" {
		full = CustomVersion + " " + full
	}

	if simple == "" || simple == "(devel)" {
		if CustomVersion != "" {
			simple = CustomVersion
		} else {
			simple = "unknown"
		}
	}

	return
}

// ActiveContext returns the currently-active context.
// This function is experimental and might be changed
// or removed in the future.
func ActiveContext() Context {
	currentCtxMu.RLock()
	defer currentCtxMu.RUnlock()
	return currentCtx
}

// CtxKey is a value type for use with context.WithValue.
type CtxKey string

// This group of variables pertains to the current configuration.
var (
	// currentCtx is the root context for the currently-running
	// configuration, which can be accessed through this value.
	// If the Config contained in this value is not nil, then
	// a config is currently active/running.
	currentCtx   Context
	currentCtxMu sync.RWMutex

	// rawCfg is the current, generic-decoded configuration;
	// we initialize it as a map with one field ("config")
	// to maintain parity with the API endpoint and to avoid
	// the special case of having to access/mutate the variable
	// directly without traversing into it.
	rawCfg = map[string]any{
		rawConfigKey: nil,
	}

	// rawCfgJSON is the JSON-encoded form of rawCfg. Keeping
	// this around avoids an extra Marshal call during changes.
	rawCfgJSON []byte

	// rawCfgIndex is the map of user-assigned ID to expanded
	// path, for converting /id/ paths to /config/ paths.
	rawCfgIndex map[string]string

	// rawCfgMu protects all the rawCfg fields and also
	// essentially synchronizes config changes/reloads.
	rawCfgMu sync.RWMutex
)

// errSameConfig is returned if the new config is the same
// as the old one. This isn't usually an actual, actionable
// error; it's mostly a sentinel value.
var errSameConfig = errors.New("config is unchanged")

// ImportPath is the package import path for Caddy core.
// This identifier may be removed in the future.
const ImportPath = "github.com/caddyserver/caddy/v2"
