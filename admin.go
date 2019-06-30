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
	"log"
	"net"
	"net/http"
	"net/http/pprof"
	"strings"
	"sync"
	"time"

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
	Listen: "localhost:2019",
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

	ln, err := net.Listen("tcp", adminConfig.Listen)
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
		route := m.New().(AdminRoute)
		mux.Handle(route.Pattern, route)
	}

	handler := cors.Default().Handler(mux)

	cfgEndptSrv = &http.Server{
		Handler:           handler,
		ReadTimeout:       5 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       5 * time.Second,
		MaxHeaderBytes:    1024 * 256,
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

var bufPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}
