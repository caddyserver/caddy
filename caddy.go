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
	"context"
	"encoding/json"
	"fmt"
	"log"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/mholt/certmagic"
)

// Config represents a Caddy configuration.
type Config struct {
	Admin *AdminConfig `json:"admin,omitempty"`

	StorageRaw json.RawMessage `json:"storage,omitempty"`
	storage    certmagic.Storage

	AppsRaw map[string]json.RawMessage `json:"apps,omitempty"`

	// apps stores the decoded Apps values,
	// keyed by module name.
	apps map[string]App

	cancelFunc context.CancelFunc
}

// App is a thing that Caddy runs.
type App interface {
	Start() error
	Stop() error
}

// Run runs Caddy with the given config.
func Run(newCfg *Config) error {
	currentCfgMu.Lock()
	defer currentCfgMu.Unlock()

	if newCfg != nil {
		// because we will need to roll back any state
		// modifications if this function errors, we
		// keep a single error value and scope all
		// sub-operations to their own functions to
		// ensure this error value does not get
		// overridden or missed when it should have
		// been set by a short assignment
		var err error

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
				cancel() // clean up now
			}
		}()
		newCfg.cancelFunc = cancel // clean up later

		// set up storage and make it CertMagic's default storage, too
		err = func() error {
			if newCfg.StorageRaw != nil {
				val, err := ctx.LoadModuleInline("module", "caddy.storage", newCfg.StorageRaw)
				if err != nil {
					return fmt.Errorf("loading storage module: %v", err)
				}
				stor, err := val.(StorageConverter).CertMagicStorage()
				if err != nil {
					return fmt.Errorf("creating storage value: %v", err)
				}
				newCfg.storage = stor
				newCfg.StorageRaw = nil // allow GC to deallocate - TODO: Does this help?
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
			for modName, rawMsg := range newCfg.AppsRaw {
				val, err := ctx.LoadModule(modName, rawMsg)
				if err != nil {
					return fmt.Errorf("loading app module '%s': %v", modName, err)
				}
				newCfg.apps[modName] = val.(App)
			}
			return nil
		}()
		if err != nil {
			return err
		}

		// Start
		err = func() error {
			var started []string
			for name, a := range newCfg.apps {
				err := a.Start()
				if err != nil {
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
		if err != nil {
			return err
		}
	}

	// swap old config with the new one
	oldCfg := currentCfg
	currentCfg = newCfg

	// Stop, Cleanup each old app
	unsyncedStop(oldCfg)

	return nil
}

// Stop stops running the current configuration.
// It is the antithesis of Run(). This function
// will log any errors that occur during the
// stopping of individual apps and continue to
// stop the others.
func Stop() error {
	currentCfgMu.Lock()
	defer currentCfgMu.Unlock()
	unsyncedStop(currentCfg)
	currentCfg = nil
	return nil
}

// unsyncedStop stops oldCfg from running, but if
// applicable, you need to acquire locks yourself.
// It is a no-op if oldCfg is nil. If any app
// returns an error when stopping, it is logged
// and the function continues with the next app.
func unsyncedStop(oldCfg *Config) {
	if oldCfg == nil {
		return
	}

	// stop each app
	for name, a := range oldCfg.apps {
		err := a.Stop()
		if err != nil {
			log.Printf("[ERROR] stop %s: %v", name, err)
		}
	}

	// clean up all old modules
	oldCfg.cancelFunc()
}

// Duration is a JSON-string-unmarshable duration type.
type Duration time.Duration

// UnmarshalJSON satisfies json.Unmarshaler.
func (d *Duration) UnmarshalJSON(b []byte) error {
	dd, err := time.ParseDuration(strings.Trim(string(b), `"`))
	if err != nil {
		return err
	}
	*d = Duration(dd)
	return nil
}

// GoModule returns the build info of this Caddy
// build from debug.BuildInfo (requires Go modules).
// If no version information is available, a non-nil
// value will still be returned, but with an
// unknown version.
func GoModule() *debug.Module {
	bi, ok := debug.ReadBuildInfo()
	if ok {
		// The recommended way to build Caddy involves
		// creating a separate main module, which
		// TODO: track related Go issue: https://github.com/golang/go/issues/29228
		for _, mod := range bi.Deps {
			if mod.Path == goModule {
				return mod
			}
		}
	}
	return &debug.Module{Version: "unknown"}
}

// goModule is the name of this Go module.
// TODO: we should be able to find this at runtime, see https://github.com/golang/go/issues/29228
const goModule = "github.com/caddyserver/caddy/v2"

// CtxKey is a value type for use with context.WithValue.
type CtxKey string

// currentCfg is the currently-loaded configuration.
var (
	currentCfg   *Config
	currentCfgMu sync.RWMutex
)
