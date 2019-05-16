package caddy2

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/mholt/certmagic"
)

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
		// was an error; otherwise, it will get
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
				val, err := ctx.LoadModuleInline("system", "caddy.storage", newCfg.StorageRaw)
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

		// Load, Provision, Validate
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

	// Stop, Cleanup
	if oldCfg != nil {
		for name, a := range oldCfg.apps {
			err := a.Stop()
			if err != nil {
				log.Printf("[ERROR] stop %s: %v", name, err)
			}
		}

		// clean up old modules
		oldCfg.cancelFunc()
	}

	return nil
}

// App is a thing that Caddy runs.
type App interface {
	Start() error
	Stop() error
}

// Config represents a Caddy configuration.
type Config struct {
	StorageRaw json.RawMessage `json:"storage"`
	storage    certmagic.Storage

	TestVal string                     `json:"testval"`
	AppsRaw map[string]json.RawMessage `json:"apps"`

	// apps stores the decoded Apps values,
	// keyed by module name.
	apps map[string]App

	cancelFunc context.CancelFunc
}

// Duration is a JSON-string-unmarshable duration type.
type Duration time.Duration

// UnmarshalJSON satisfies json.Unmarshaler.
func (d *Duration) UnmarshalJSON(b []byte) error {
	dd, err := time.ParseDuration(strings.Trim(string(b), `"`))
	if err != nil {
		return err
	}
	cd := Duration(dd)
	d = &cd
	return nil
}

// CtxKey is a value type for use with context.WithValue.
type CtxKey string

// currentCfg is the currently-loaded configuration.
var (
	currentCfg   *Config
	currentCfgMu sync.RWMutex
)
