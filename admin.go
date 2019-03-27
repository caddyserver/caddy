package caddy2

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/pprof"
	"strings"
	"sync"
	"time"
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

	///// BEGIN PPROF STUFF (TODO: Temporary) /////
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	///// END PPROF STUFF //////

	for _, m := range GetModules("admin") {
		moduleValue, err := m.New()
		if err != nil {
			return fmt.Errorf("initializing module '%s': %v", m.Name, err)
		}
		route := moduleValue.(AdminRoute)
		mux.Handle(route.Pattern, route)
	}

	cfgEndptSrv = &http.Server{
		Handler:           mux,
		ReadTimeout:       5 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       5 * time.Second,
		MaxHeaderBytes:    1024 * 256,
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
	r.Close = true
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
	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufPool.Put(buf)

	_, err := io.Copy(buf, io.LimitReader(r, 1024*1024))
	if err != nil {
		return err
	}

	var cfg Config
	err = json.Unmarshal(buf.Bytes(), &cfg)
	if err != nil {
		return fmt.Errorf("decoding config: %v", err)
	}

	err = Start(cfg)
	if err != nil {
		return fmt.Errorf("starting: %v", err)
	}

	return nil
}

var bufPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}
