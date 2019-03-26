package caddy2

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
)

var (
	cfgEndptSrv   *http.Server
	cfgEndptSrvMu sync.Mutex
)

// Start starts Caddy's administration endpoint.
func Start(addr string) error {
	cfgEndptSrvMu.Lock()
	defer cfgEndptSrvMu.Unlock()

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/load", handleLoadConfig)

	for _, m := range GetModules("admin") {
		moduleValue, err := m.New()
		if err != nil {
			return fmt.Errorf("initializing module '%s': %v", m.Name, err)
		}
		route := moduleValue.(AdminRoute)
		mux.Handle(route.Pattern, route)
	}

	cfgEndptSrv = &http.Server{
		Handler: mux,
	}

	go cfgEndptSrv.Serve(ln)

	return nil
}

// AdminRoute represents a route for the admin endpoint.
type AdminRoute struct {
	http.Handler
	Pattern string
}

// Stop stops the API endpoint.
func Stop() error {
	cfgEndptSrvMu.Lock()
	defer cfgEndptSrvMu.Unlock()

	if cfgEndptSrv == nil {
		return fmt.Errorf("no server")
	}

	err := cfgEndptSrv.Shutdown(context.Background()) // TODO
	if err != nil {
		return fmt.Errorf("shutting down server: %v", err)
	}

	cfgEndptSrv = nil

	return nil
}

func handleLoadConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	if !strings.Contains(r.Header.Get("Content-Type"), "/json") {
		http.Error(w, "unacceptable Content-Type", http.StatusBadRequest)
		return
	}

	err := Load(r.Body)
	if err != nil {
		log.Printf("[ADMIN][ERROR] loading config: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
}

// Load loads a configuration.
func Load(r io.Reader) error {
	gc := globalConfig{modules: make(map[string]interface{})}
	err := json.NewDecoder(r).Decode(&gc)
	if err != nil {
		return fmt.Errorf("decoding config: %v", err)
	}

	for modName, rawMsg := range gc.Modules {
		mod, ok := modules[modName]
		if !ok {
			return fmt.Errorf("unrecognized module: %s", modName)
		}

		if mod.New != nil {
			val, err := mod.New()
			if err != nil {
				return fmt.Errorf("initializing module '%s': %v", modName, err)
			}
			err = json.Unmarshal(rawMsg, &val)
			if err != nil {
				return fmt.Errorf("decoding module config: %s: %v", modName, err)
			}
			gc.modules[modName] = val
		}
	}

	return nil
}

type globalConfig struct {
	TestVal string                     `json:"testval"`
	Modules map[string]json.RawMessage `json:"modules"`
	TestArr []string                   `json:"test_arr"`
	modules map[string]interface{}
}
