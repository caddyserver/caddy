package caddy2

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mholt/certmagic"
)

// Run runs Caddy with the given config.
func Run(cfg *Config) error {
	// allow only one call to Start at a time,
	// since various calls to LoadModule()
	// access shared map moduleInstances
	startMu.Lock()
	defer startMu.Unlock()

	// because we will need to roll back any state
	// modifications if this function errors, we
	// keep a single error value and scope all
	// sub-operations to their own functions to
	// ensure this error value does not get
	// overridden or missed when it should have
	// been set by a short assignment
	var err error

	// prepare the new config for use
	cfg.apps = make(map[string]App)
	cfg.moduleStates = make(map[string]interface{})

	// reset the shared moduleInstances map; but
	// keep a temporary reference to the current
	// one so we can transfer over any necessary
	// state to the new modules or to roll back
	// if necessary
	oldModuleInstances := moduleInstances
	defer func() {
		if err != nil {
			moduleInstances = oldModuleInstances
		}
	}()
	moduleInstances = make(map[string][]interface{})

	// set up storage and make it CertMagic's default storage, too
	err = func() error {
		if cfg.StorageRaw != nil {
			val, err := LoadModuleInline("system", "caddy.storage", cfg.StorageRaw)
			if err != nil {
				return fmt.Errorf("loading storage module: %v", err)
			}
			stor, err := val.(StorageConverter).CertMagicStorage()
			if err != nil {
				return fmt.Errorf("creating storage value: %v", err)
			}
			cfg.storage = stor
			cfg.StorageRaw = nil // allow GC to deallocate - TODO: Does this help?
		}
		if cfg.storage == nil {
			cfg.storage = &certmagic.FileStorage{Path: dataDir()}
		}
		certmagic.Default.Storage = cfg.storage

		return nil
	}()
	if err != nil {
		return err
	}

	// Load, Provision, Validate
	err = func() error {
		for modName, rawMsg := range cfg.AppsRaw {
			val, err := LoadModule(modName, rawMsg)
			if err != nil {
				return fmt.Errorf("loading app module '%s': %v", modName, err)
			}
			cfg.apps[modName] = val.(App)
		}
		return nil
	}()
	if err != nil {
		return err
	}

	// swap old config with the new one, and
	// roll back this change if anything fails
	currentCfgMu.Lock()
	oldCfg := currentCfg
	currentCfg = cfg
	currentCfgMu.Unlock()
	defer func() {
		if err != nil {
			currentCfgMu.Lock()
			currentCfg = oldCfg
			currentCfgMu.Unlock()
		}
	}()

	// OnLoad
	err = func() error {
		for modName, instances := range moduleInstances {
			mod, err := GetModule(modName)
			if err != nil {
				return err
			}
			if mod.OnLoad != nil {
				var priorState interface{}
				if oldCfg != nil {
					priorState = oldCfg.moduleStates[modName]
				}
				modState, err := mod.OnLoad(instances, priorState)
				if err != nil {
					return fmt.Errorf("module OnLoad: %s: %v", modName, err)
				}
				if modState != nil {
					cfg.moduleStates[modName] = modState
				}
			}
		}
		return nil
	}()
	if err != nil {
		return err
	}

	// Start
	err = func() error {
		h := Handle{cfg}
		for name, a := range cfg.apps {
			err := a.Start(h)
			if err != nil {
				for otherAppName, otherApp := range cfg.apps {
					err := otherApp.Stop()
					if err != nil {
						log.Printf("aborting app %s: %v", otherAppName, err)
					}
				}
				return fmt.Errorf("%s app module: start: %v", name, err)
			}
		}
		return nil
	}()
	if err != nil {
		return err
	}

	// Stop
	if oldCfg != nil {
		for name, a := range oldCfg.apps {
			err := a.Stop()
			if err != nil {
				log.Printf("[ERROR] stop %s: %v", name, err)
			}
		}
	}

	// OnUnload
	err = func() error {
		for modName := range oldModuleInstances {
			mod, err := GetModule(modName)
			if err != nil {
				return err
			}
			if mod.OnUnload != nil {
				var unloadingState interface{}
				if oldCfg != nil {
					unloadingState = oldCfg.moduleStates[modName]
				}
				err := mod.OnUnload(unloadingState)
				if err != nil {
					log.Printf("[ERROR] module OnUnload: %s: %v", modName, err)
					continue
				}
			}
		}
		return nil
	}()
	if err != nil {
		return err
	}

	// shut down listeners that are no longer being used
	err = func() error {
		listenersMu.Lock()
		for key, info := range listeners {
			if atomic.LoadInt32(&info.usage) == 0 {
				err := info.ln.Close()
				if err != nil {
					log.Printf("[ERROR] closing listener %s: %v", info.ln.Addr(), err)
					continue
				}
				delete(listeners, key)
			}
		}
		listenersMu.Unlock()
		return nil
	}()
	if err != nil {
		return err
	}

	return nil
}

// App is a thing that Caddy runs.
type App interface {
	Start(Handle) error
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

	// moduleStates stores the optional "global" state
	// values of every module used by this configuration,
	// keyed by module name.
	moduleStates map[string]interface{}
}

// Handle allows app modules to access
// the top-level Config in a controlled
// manner without needing to rely on
// global state.
type Handle struct {
	current *Config
}

// App returns the configured app named name.
// A nil value is returned if no app with that
// name is currently configured.
func (h Handle) App(name string) interface{} {
	return h.current.apps[name]
}

// GetStorage returns the configured Caddy storage implementation.
// If no storage implementation is explicitly configured, the
// default one is returned instead, as long as there is a current
// configuration loaded.
func GetStorage() certmagic.Storage {
	currentCfgMu.RLock()
	defer currentCfgMu.RUnlock()
	if currentCfg == nil {
		return nil
	}
	return currentCfg.storage
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

// moduleInstances stores the individual instantiated
// values of modules, keyed by module name. The list
// of instances of each module get passed into the
// respective module's OnLoad callback, so they can
// set up any global state and/or make sure their
// configuration, when viewed as a whole, is valid.
// Since this list is shared, only one Start() routine
// must be allowed to happen at any given time.
var moduleInstances = make(map[string][]interface{})

// startMu ensures that only one Start() happens at a time.
// This is important since moduleInstances is shared state.
var startMu sync.Mutex
