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
	"io/ioutil"
	"log"
	"mime"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/mholt/certmagic"
	"github.com/rs/cors"
)

var (
	cfgEndptSrv   *http.Server
	cfgEndptSrvMu sync.Mutex
)

// AdminConfig configures the admin endpoint.
type AdminConfig struct {
	Listen string `json:"listen,omitempty"`
}

// DefaultAdminConfig is the default configuration
// for the administration endpoint.
var DefaultAdminConfig = &AdminConfig{
	Listen: DefaultAdminListen,
}

// StartAdmin starts Caddy's administration endpoint,
// bootstrapping it with an optional configuration
// in the format of JSON bytes. It opens a listener
// resource. When no longer needed, StopAdmin should
// be called.
func StartAdmin(initialConfigJSON []byte) error {
	cfgEndptSrvMu.Lock()
	defer cfgEndptSrvMu.Unlock()

	adminConfig := DefaultAdminConfig
	if len(initialConfigJSON) > 0 {
		var config *Config
		err := json.Unmarshal(initialConfigJSON, &config)
		if err != nil {
			return fmt.Errorf("unmarshaling bootstrap config: %v", err)
		}
		if config != nil && config.Admin != nil {
			adminConfig = config.Admin
		}
		if cfgEndptSrv != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			err := cfgEndptSrv.Shutdown(ctx)
			if err != nil {
				return fmt.Errorf("shutting down old admin endpoint: %v", err)
			}
		}
	}

	// extract a singular listener address
	netw, listenAddrs, err := ParseNetworkAddress(adminConfig.Listen)
	if err != nil {
		return fmt.Errorf("parsing admin listener address: %v", err)
	}
	if len(listenAddrs) != 1 {
		return fmt.Errorf("admin endpoint must have exactly one address; cannot listen on %v", listenAddrs)
	}
	ln, err := net.Listen(netw, listenAddrs[0])
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/load", handleLoadConfig)
	mux.HandleFunc("/stop", handleStop)

	///// BEGIN PPROF STUFF (TODO: Temporary) /////
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	///// END PPROF STUFF //////

	for _, m := range GetModules("admin.routers") {
		adminrtr := m.New().(AdminRouter)
		for _, route := range adminrtr.Routes() {
			mux.Handle(route.Pattern, route)
		}
	}

	handler := cors.Default().Handler(mux)

	cfgEndptSrv = &http.Server{
		Handler:           handler,
		ReadTimeout:       5 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       5 * time.Second,
		MaxHeaderBytes:    1024 * 64,
	}

	go cfgEndptSrv.Serve(ln)

	log.Println("Caddy 2 admin endpoint listening on", adminConfig.Listen)

	if len(initialConfigJSON) > 0 {
		err := Load(bytes.NewReader(initialConfigJSON))
		if err != nil {
			return fmt.Errorf("loading initial config: %v", err)
		}
		log.Println("Caddy 2 serving initial configuration")
	}

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

// AdminRouter is a type which can return routes for the admin API.
type AdminRouter interface {
	Routes() []AdminRoute
}

// AdminRoute represents a route for the admin endpoint.
type AdminRoute struct {
	http.Handler
	Pattern string
}

func handleLoadConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	// if the config is formatted other than Caddy's native
	// JSON, we need to adapt it before loading it
	if ctHeader := r.Header.Get("Content-Type"); ctHeader != "" {
		ct, _, err := mime.ParseMediaType(ctHeader)
		if err != nil {
			http.Error(w, "Invalid Content-Type: "+err.Error(), http.StatusBadRequest)
			return
		}
		if !strings.HasSuffix(ct, "/json") {
			slashIdx := strings.Index(ct, "/")
			if slashIdx < 0 {
				http.Error(w, "Malformed Content-Type", http.StatusBadRequest)
				return
			}
			adapterName := ct[slashIdx+1:]
			cfgAdapter := caddyconfig.GetAdapter(adapterName)
			if cfgAdapter == nil {
				http.Error(w, "Unrecognized config adapter: "+adapterName, http.StatusBadRequest)
				return
			}
			body, err := ioutil.ReadAll(http.MaxBytesReader(w, r.Body, 1024*1024))
			if err != nil {
				http.Error(w, "Error reading request body: "+err.Error(), http.StatusBadRequest)
				return
			}
			result, warnings, err := cfgAdapter.Adapt(body, nil)
			if err != nil {
				log.Printf("[ADMIN][ERROR] adapting config from %s: %v", adapterName, err)
				http.Error(w, fmt.Sprintf("Adapting config from %s: %v", adapterName, err), http.StatusBadRequest)
				return
			}
			if len(warnings) > 0 {
				respBody, err := json.Marshal(warnings)
				if err != nil {
					log.Printf("[ADMIN][ERROR] marshaling warnings: %v", err)
				}
				w.Write(respBody)
			}
			// replace original request body with adapted JSON
			r.Body.Close()
			r.Body = ioutil.NopCloser(bytes.NewReader(result))
		}
	}

	// pass this off to the /config/ endpoint
	r.URL.Path = "/" + rawConfigKey + "/"
	handleConfig(w, r)
}

func handleStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	log.Println("[ADMIN] Initiating shutdown")
	if err := stopAndCleanup(); err != nil {
		log.Printf("[ADMIN][ERROR] stopping: %v \n", err)
	}
	log.Println("[ADMIN] Exiting")
	os.Exit(0)
}

func stopAndCleanup() error {
	if err := Stop(); err != nil {
		return err
	}
	certmagic.CleanUpOwnLocks()
	return nil
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

	var cfg *Config
	err = json.Unmarshal(buf.Bytes(), &cfg)
	if err != nil {
		return fmt.Errorf("decoding config: %v", err)
	}

	err = Run(cfg)
	if err != nil {
		return fmt.Errorf("running: %v", err)
	}

	return nil
}

// DefaultAdminListen is the address for the admin
// listener, if none is specified at startup.
var DefaultAdminListen = "localhost:2019"

var bufPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}
