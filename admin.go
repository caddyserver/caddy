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

// StartAdmin starts Caddy's administration endpoint.
func StartAdmin(addr string) error {
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

// StopAdmin stops the API endpoint.
func StopAdmin() error {
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

// AdminRoute represents a route for the admin endpoint.
type AdminRoute struct {
	http.Handler
	Pattern string
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

// Load loads and starts a configuration.
func Load(r io.Reader) error {
	var cfg Config
	err := json.NewDecoder(r).Decode(&cfg)
	if err != nil {
		return fmt.Errorf("decoding config: %v", err)
	}
	err = Start(cfg)
	if err != nil {
		return fmt.Errorf("starting: %v", err)
	}
	return nil
}
