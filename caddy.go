package caddy2

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Start runs Caddy with the given config.
func Start(cfg Config) error {
	// allow only one call to Start at a time,
	// since various calls to LoadModule()
	// access shared map moduleInstances
	startMu.Lock()
	defer startMu.Unlock()

	// prepare the config for use
	cfg.runners = make(map[string]Runner)
	cfg.moduleStates = make(map[string]interface{})

	// reset the shared moduleInstances map; but
	// keep a temporary reference to the current
	// one so we can transfer over any necessary
	// state to the new modules; or in case this
	// function returns an error, we need to put
	// the "old" one back where we found it
	var err error
	oldModuleInstances := moduleInstances
	defer func() {
		if err != nil {
			moduleInstances = oldModuleInstances
		}
	}()
	moduleInstances = make(map[string][]interface{})

	// load (decode) each runner module
	for modName, rawMsg := range cfg.Modules {
		val, err := LoadModule(modName, rawMsg)
		if err != nil {
			return fmt.Errorf("loading module '%s': %v", modName, err)
		}
		cfg.runners[modName] = val.(Runner)
	}

	// start the new runners
	for name, r := range cfg.runners {
		err := r.Run()
		if err != nil {
			// TODO: If any one has an error, stop the others
			return fmt.Errorf("%s module: %v", name, err)
		}
	}

	// shut down down the old runners
	currentCfgMu.Lock()
	if currentCfg != nil {
		for name, r := range currentCfg.runners {
			err := r.Cancel()
			if err != nil {
				log.Printf("[ERROR] cancel %s: %v", name, err)
			}
		}
	}
	oldCfg := currentCfg
	currentCfg = &cfg
	currentCfgMu.Unlock()

	// invoke unload callbacks on old configuration
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

	// invoke load callbacks on new configuration
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

	// shut down listeners that are no longer being used
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
}

// Runner is a thing that Caddy runs.
type Runner interface {
	Run() error
	Cancel() error
}

// Config represents a Caddy configuration.
type Config struct {
	TestVal string                     `json:"testval"`
	Modules map[string]json.RawMessage `json:"modules"`

	// runners stores the decoded Modules values,
	// keyed by module name.
	runners map[string]Runner

	// moduleStates stores the optional "global" state
	// values of every module used by this configuration,
	// keyed by module name.
	moduleStates map[string]interface{}
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

// MarshalJSON satisfies json.Marshaler.
func (d Duration) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`"%s"`, time.Duration(d).String())), nil
}

// currentCfg is the currently-loaded configuration.
var (
	currentCfg   *Config
	currentCfgMu sync.Mutex
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
// This is important since
var startMu sync.Mutex
