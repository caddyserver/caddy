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

package caddyhttp

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"text/template"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	caddycmd "github.com/caddyserver/caddy/v2/cmd"
)

func init() {
	caddy.RegisterModule(StaticResponse{})
	caddycmd.RegisterCommand(caddycmd.Command{
		Name:  "respond",
		Func:  cmdRespond,
		Usage: "[--status <code>] <body>",
		Short: "Simple, hard-coded HTTP responses for development and testing",
		Long: `
Spins up a quick-and-clean HTTP server for development and testing purposes.

With no options specified, this command listens on a random available port
and answers HTTP requests with an empty 200 response. The listen address can
be customized with the --listen flag and will always be printed to stdout.

The body may be specified as the final (and unnamed) argument to the command,
or piped via stdin. Template evaluation is enabled, with the following extra
variables available:
`,
		Flags: func() *flag.FlagSet {
			fs := flag.NewFlagSet("respond", flag.ExitOnError)
			fs.String("listen", ":0", "The address to which to bind the listener")
			fs.Int("status", http.StatusOK, "The response status code")
			fs.Bool("access-log", false, "Enable the access log")
			fs.Bool("debug", false, "Enable more verbose debug-level logging")
			return fs
		}(),
	})
}

// StaticResponse implements a simple responder for static responses.
type StaticResponse struct {
	// The HTTP status code to respond with. Can be an integer or,
	// if needing to use a placeholder, a string.
	StatusCode WeakString `json:"status_code,omitempty"`

	// Header fields to set on the response.
	Headers http.Header `json:"headers,omitempty"`

	// The response body.
	Body string `json:"body,omitempty"`

	// If true, the server will close the client's connection
	// after writing the response.
	Close bool `json:"close,omitempty"`

	// Immediately and forcefully closes the connection without
	// writing a response. Interrupts any other HTTP streams on
	// the same connection.
	Abort bool `json:"abort,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (StaticResponse) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.static_response",
		New: func() caddy.Module { return new(StaticResponse) },
	}
}

// UnmarshalCaddyfile sets up the handler from Caddyfile tokens. Syntax:
//
//     respond [<matcher>] <status>|<body> [<status>] {
//         body <text>
//         close
//     }
//
// If there is just one argument (other than the matcher), it is considered
// to be a status code if it's a valid positive integer of 3 digits.
func (s *StaticResponse) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		args := d.RemainingArgs()
		switch len(args) {
		case 1:
			if len(args[0]) == 3 {
				if num, err := strconv.Atoi(args[0]); err == nil && num > 0 {
					s.StatusCode = WeakString(args[0])
					break
				}
			}
			s.Body = args[0]
		case 2:
			s.Body = args[0]
			s.StatusCode = WeakString(args[1])
		default:
			return d.ArgErr()
		}

		for d.NextBlock(0) {
			switch d.Val() {
			case "body":
				if s.Body != "" {
					return d.Err("body already specified")
				}
				if !d.AllArgs(&s.Body) {
					return d.ArgErr()
				}
			case "close":
				if s.Close {
					return d.Err("close already specified")
				}
				s.Close = true
			default:
				return d.Errf("unrecognized subdirective '%s'", d.Val())
			}
		}
	}
	return nil
}

func (s StaticResponse) ServeHTTP(w http.ResponseWriter, r *http.Request, _ Handler) error {
	// close the connection immediately
	if s.Abort {
		panic(http.ErrAbortHandler)
	}

	// close the connection after responding
	if s.Close {
		r.Close = true
		w.Header().Set("Connection", "close")
	}

	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

	// set all headers
	for field, vals := range s.Headers {
		field = repl.ReplaceAll(field, "")
		newVals := make([]string, len(vals))
		for i := range vals {
			newVals[i] = repl.ReplaceAll(vals[i], "")
		}
		w.Header()[field] = newVals
	}

	// do not allow Go to sniff the content-type
	if w.Header().Get("Content-Type") == "" {
		w.Header()["Content-Type"] = nil
	}

	// get the status code; if this handler exists in an error route,
	// use the recommended status code as the default; otherwise 200
	statusCode := http.StatusOK
	if reqErr, ok := r.Context().Value(ErrorCtxKey).(error); ok {
		if handlerErr, ok := reqErr.(HandlerError); ok {
			if handlerErr.StatusCode > 0 {
				statusCode = handlerErr.StatusCode
			}
		}
	}
	if codeStr := s.StatusCode.String(); codeStr != "" {
		intVal, err := strconv.Atoi(repl.ReplaceAll(codeStr, ""))
		if err != nil {
			return Error(http.StatusInternalServerError, err)
		}
		statusCode = intVal
	}

	// write headers
	w.WriteHeader(statusCode)

	// write response body
	if s.Body != "" {
		fmt.Fprint(w, repl.ReplaceKnown(s.Body, ""))
	}

	return nil
}

func cmdRespond(fl caddycmd.Flags) (int, error) {
	caddy.TrapSignals()

	// get flag values
	listen := fl.String("listen")
	statusCode := fl.Int("status")
	accessLog := fl.Bool("access-log")
	debug := fl.Bool("debug")

	// get response body, either from arg or piped in
	body := fl.Arg(0)
	if body == "" {
		stdinInfo, err := os.Stdin.Stat()
		if err != nil {
			return caddy.ExitCodeFailedStartup, err
		}
		if stdinInfo.Mode()&os.ModeNamedPipe != 0 {
			bodyBytes, err := io.ReadAll(os.Stdin)
			if err != nil {
				return caddy.ExitCodeFailedStartup, err
			}
			body = string(bodyBytes)
		}
	}

	// expand listen address, if more than one port
	listenAddr, err := caddy.ParseNetworkAddress(listen)
	if err != nil {
		return caddy.ExitCodeFailedStartup, err
	}
	listenAddrs := make([]string, 0, listenAddr.PortRangeSize())
	for offset := uint(0); offset < listenAddr.PortRangeSize(); offset++ {
		listenAddrs = append(listenAddrs, listenAddr.JoinHostPort(offset))
	}

	// build each HTTP server
	httpApp := App{Servers: make(map[string]*Server)}

	for i, addr := range listenAddrs {
		var handlers []json.RawMessage

		// response body supports a basic template; evaluate it
		tplCtx := struct {
			N       int    // server number
			Port    uint   // only the port
			Address string // listener address
		}{
			N:       i,
			Port:    listenAddr.StartPort + uint(i),
			Address: addr,
		}
		tpl, err := template.New("body").Parse(body)
		if err != nil {
			return caddy.ExitCodeFailedStartup, err
		}
		buf := new(bytes.Buffer)
		err = tpl.Execute(buf, tplCtx)
		if err != nil {
			return caddy.ExitCodeFailedStartup, err
		}

		// create route with handler
		handler := StaticResponse{Body: buf.String(), StatusCode: WeakString(fmt.Sprintf("%d", statusCode))}
		handlers = append(handlers, caddyconfig.JSONModuleObject(handler, "handler", "static_response", nil))
		route := Route{HandlersRaw: handlers}

		server := &Server{
			Listen:            []string{addr},
			ReadHeaderTimeout: caddy.Duration(10 * time.Second),
			IdleTimeout:       caddy.Duration(30 * time.Second),
			MaxHeaderBytes:    1024 * 10,
			Routes:            RouteList{route},
			AutoHTTPS:         &AutoHTTPSConfig{DisableRedir: true},
		}
		if accessLog {
			server.Logs = new(ServerLogConfig)
		}

		// save server
		httpApp.Servers[fmt.Sprintf("static%d", i)] = server
	}

	// finish building the config
	var false bool
	cfg := &caddy.Config{
		Admin: &caddy.AdminConfig{
			Disabled: true,
			Config: &caddy.ConfigSettings{
				Persist: &false,
			},
		},
		AppsRaw: caddy.ModuleMap{
			"http": caddyconfig.JSON(httpApp, nil),
		},
	}
	if debug {
		cfg.Logging = &caddy.Logging{
			Logs: map[string]*caddy.CustomLog{
				"default": {Level: "DEBUG"},
			},
		}
	}

	// run it!
	err = caddy.Run(cfg)
	if err != nil {
		return caddy.ExitCodeFailedStartup, err
	}

	// to print listener addresses, get the active HTTP app
	loadedHTTPApp, err := caddy.ActiveContext().App("http")
	if err != nil {
		return caddy.ExitCodeFailedStartup, err
	}

	// print each listener address
	for _, srv := range loadedHTTPApp.(*App).Servers {
		for _, ln := range srv.listeners {
			fmt.Printf("Server address: %s\n", ln.Addr())
		}
	}

	select {}
}

// Interface guards
var (
	_ MiddlewareHandler     = (*StaticResponse)(nil)
	_ caddyfile.Unmarshaler = (*StaticResponse)(nil)
)
