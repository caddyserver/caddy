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
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"os"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func init() {
	caddy.RegisterModule(StaticResponse{})
	caddycmd.RegisterCommand(caddycmd.Command{
		Name:  "respond",
		Usage: `[--status <code>] [--body <content>] [--listen <addr>] [--access-log] [--debug] [--header "Field: value"] <body|status>`,
		Short: "Simple, hard-coded HTTP responses for development and testing",
		Long: `
Spins up a quick-and-clean HTTP server for development and testing purposes.

With no options specified, this command listens on a random available port
and answers HTTP requests with an empty 200 response. The listen address can
be customized with the --listen flag and will always be printed to stdout.
If the listen address includes a port range, multiple servers will be started.

If a final, unnamed argument is given, it will be treated as a status code
(same as the --status flag) if it is a 3-digit number. Otherwise, it is used
as the response body (same as the --body flag). The --status and --body flags
will always override this argument (for example, to write a body that
literally says "404" but with a status code of 200, do '--status 200 404').

A body may be given in 3 ways: a flag, a final (and unnamed) argument to
the command, or piped to stdin (if flag and argument are unset). Limited
template evaluation is supported on the body, with the following variables:

	{{.N}}        The server number (useful if using a port range)
	{{.Port}}     The listener port
	{{.Address}}  The listener address

(See the docs for the text/template package in the Go standard library for
information about using templates: https://pkg.go.dev/text/template)

Access/request logging and more verbose debug logging can also be enabled.

Response headers may be added using the --header flag for each header field.
`,
		CobraFunc: func(cmd *cobra.Command) {
			cmd.Flags().StringP("listen", "l", ":0", "The address to which to bind the listener")
			cmd.Flags().IntP("status", "s", http.StatusOK, "The response status code")
			cmd.Flags().StringP("body", "b", "", "The body of the HTTP response")
			cmd.Flags().BoolP("access-log", "", false, "Enable the access log")
			cmd.Flags().BoolP("debug", "v", false, "Enable more verbose debug-level logging")
			cmd.Flags().StringSliceP("header", "H", []string{}, "Set a header on the response (format: \"Field: value\")")
			cmd.RunE = caddycmd.WrapCommandFuncForCobra(cmdRespond)
		},
	})
}

// StaticResponse implements a simple responder for static responses.
type StaticResponse struct {
	// The HTTP status code to respond with. Can be an integer or,
	// if needing to use a placeholder, a string.
	//
	// If the status code is 103 (Early Hints), the response headers
	// will be written to the client immediately, the body will be
	// ignored, and the next handler will be invoked. This behavior
	// is EXPERIMENTAL while RFC 8297 is a draft, and may be changed
	// or removed.
	StatusCode WeakString `json:"status_code,omitempty"`

	// Header fields to set on the response; overwrites any existing
	// header fields of the same names after normalization.
	Headers http.Header `json:"headers,omitempty"`

	// The response body. If non-empty, the Content-Type header may
	// be added automatically if it is not explicitly configured nor
	// already set on the response; the default value is
	// "text/plain; charset=utf-8" unless the body is a valid JSON object
	// or array, in which case the value will be "application/json".
	// Other than those common special cases the Content-Type header
	// should be set explicitly if it is desired because MIME sniffing
	// is disabled for safety.
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
//	respond [<matcher>] <status>|<body> [<status>] {
//	    body <text>
//	    close
//	}
//
// If there is just one argument (other than the matcher), it is considered
// to be a status code if it's a valid positive integer of 3 digits.
func (s *StaticResponse) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume directive name
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
	return nil
}

func (s StaticResponse) ServeHTTP(w http.ResponseWriter, r *http.Request, next Handler) error {
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
		field = textproto.CanonicalMIMEHeaderKey(repl.ReplaceAll(field, ""))
		newVals := make([]string, len(vals))
		for i := range vals {
			newVals[i] = repl.ReplaceAll(vals[i], "")
		}
		w.Header()[field] = newVals
	}

	// implicitly set Content-Type header if we can do so safely
	// (this allows templates handler to eval templates successfully
	// or for clients to render JSON properly which is very common)
	body := repl.ReplaceKnown(s.Body, "")
	if body != "" && w.Header().Get("Content-Type") == "" {
		content := strings.TrimSpace(body)
		if len(content) > 2 &&
			(content[0] == '{' && content[len(content)-1] == '}' ||
				(content[0] == '[' && content[len(content)-1] == ']')) &&
			json.Valid([]byte(content)) {
			w.Header().Set("Content-Type", "application/json")
		} else {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		}
	}

	// do not allow Go to sniff the content-type, for safety
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
	if statusCode != http.StatusEarlyHints && body != "" {
		fmt.Fprint(w, body)
	}

	// continue handling after Early Hints as they are not the final response
	if statusCode == http.StatusEarlyHints {
		return next.ServeHTTP(w, r)
	}

	return nil
}

func buildHTTPServer(i int, port uint, addr string, statusCode int, hdr http.Header, body string, accessLog bool) (*Server, error) {
	var handlers []json.RawMessage

	// response body supports a basic template; evaluate it
	tplCtx := struct {
		N       int    // server number
		Port    uint   // only the port
		Address string // listener address
	}{
		N:       i,
		Port:    port,
		Address: addr,
	}
	tpl, err := template.New("body").Parse(body)
	if err != nil {
		return nil, err
	}
	buf := new(bytes.Buffer)
	err = tpl.Execute(buf, tplCtx)
	if err != nil {
		return nil, err
	}

	// create route with handler
	handler := StaticResponse{
		StatusCode: WeakString(fmt.Sprintf("%d", statusCode)),
		Headers:    hdr,
		Body:       buf.String(),
	}
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

	return server, nil
}

func cmdRespond(fl caddycmd.Flags) (int, error) {
	caddy.TrapSignals()

	// get flag values
	listen := fl.String("listen")
	statusCodeFl := fl.Int("status")
	bodyFl := fl.String("body")
	accessLog := fl.Bool("access-log")
	debug := fl.Bool("debug")
	arg := fl.Arg(0)

	if fl.NArg() > 1 {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("too many unflagged arguments")
	}

	// prefer status and body from explicit flags
	statusCode, body := statusCodeFl, bodyFl

	// figure out if status code was explicitly specified; this lets
	// us set a non-zero value as the default but is a little hacky
	var statusCodeFlagSpecified bool
	for _, fl := range os.Args {
		if fl == "--status" {
			statusCodeFlagSpecified = true
			break
		}
	}

	// try to determine what kind of parameter the unnamed argument is
	if arg != "" {
		// specifying body and status flags makes the argument redundant/unused
		if bodyFl != "" && statusCodeFlagSpecified {
			return caddy.ExitCodeFailedStartup, fmt.Errorf("unflagged argument \"%s\" is overridden by flags", arg)
		}

		// if a valid 3-digit number, treat as status code; otherwise body
		if argInt, err := strconv.Atoi(arg); err == nil && !statusCodeFlagSpecified {
			if argInt >= 100 && argInt <= 999 {
				statusCode = argInt
			}
		} else if body == "" {
			body = arg
		}
	}

	// if we still need a body, see if stdin is being piped
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

	// build headers map
	headers, err := fl.GetStringSlice("header")
	if err != nil {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("invalid header flag: %v", err)
	}
	hdr := make(http.Header)
	for i, h := range headers {
		key, val, found := strings.Cut(h, ":")
		key, val = strings.TrimSpace(key), strings.TrimSpace(val)
		if !found || key == "" || val == "" {
			return caddy.ExitCodeFailedStartup, fmt.Errorf("header %d: invalid format \"%s\" (expecting \"Field: value\")", i, h)
		}
		hdr.Set(key, val)
	}

	// build each HTTP server
	httpApp := App{Servers: make(map[string]*Server)}

	// expand listen address, if more than one port
	listenAddr, err := caddy.ParseNetworkAddress(listen)
	if err != nil {
		return caddy.ExitCodeFailedStartup, err
	}

	if !listenAddr.IsUnixNetwork() && !listenAddr.IsFdNetwork() {
		listenAddrs := make([]string, 0, listenAddr.PortRangeSize())
		for offset := uint(0); offset < listenAddr.PortRangeSize(); offset++ {
			listenAddrs = append(listenAddrs, listenAddr.JoinHostPort(offset))
		}

		for i, addr := range listenAddrs {
			server, err := buildHTTPServer(i, listenAddr.StartPort+uint(i), addr, statusCode, hdr, body, accessLog)
			if err != nil {
				return caddy.ExitCodeFailedStartup, err
			}

			// save server
			httpApp.Servers[fmt.Sprintf("static%d", i)] = server
		}
	} else {
		server, err := buildHTTPServer(0, 0, listen, statusCode, hdr, body, accessLog)
		if err != nil {
			return caddy.ExitCodeFailedStartup, err
		}

		// save server
		httpApp.Servers[fmt.Sprintf("static%d", 0)] = server
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
				"default": {BaseLog: caddy.BaseLog{Level: zap.DebugLevel.CapitalString()}},
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
