package caddy2

import (
	"encoding/json"
	"fmt"
	"log"
	"runtime/debug"
	"strings"
	"sync"
	"time"
)

var currentCfg *Config
var currentCfgMu sync.Mutex

// Start runs Caddy with the given config.
func Start(cfg Config) error {
	cfg.runners = make(map[string]Runner)

	for modName, rawMsg := range cfg.Modules {
		mod, ok := modules[modName]
		if !ok {
			return fmt.Errorf("unrecognized module: %s", modName)
		}
		val, err := LoadModule(mod, rawMsg)
		if err != nil {
			return fmt.Errorf("loading module '%s': %v", modName, err)
		}
		cfg.runners[modName] = val.(Runner)
	}

	for name, r := range cfg.runners {
		err := r.Run()
		if err != nil {
			// TODO: If any one has an error, stop the others
			return fmt.Errorf("%s module: %v", name, err)
		}
	}

	currentCfgMu.Lock()
	if currentCfg != nil {
		for _, r := range cfg.runners {
			err := r.Cancel()
			if err != nil {
				log.Println(err)
			}
		}
	}
	currentCfg = &cfg
	currentCfgMu.Unlock()

	// TODO: debugging memory leak...
	debug.FreeOSMemory()

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
	runners map[string]Runner
}

// Duration is a JSON-string-unmarshable duration type.
type Duration time.Duration

// UnmarshalJSON satisfies json.Unmarshaler.
func (d *Duration) UnmarshalJSON(b []byte) (err error) {
	dd, err := time.ParseDuration(strings.Trim(string(b), `"`))
	cd := Duration(dd)
	d = &cd
	return
}

// MarshalJSON satisfies json.Marshaler.
func (d Duration) MarshalJSON() (b []byte, err error) {
	return []byte(fmt.Sprintf(`"%s"`, time.Duration(d).String())), nil
}
