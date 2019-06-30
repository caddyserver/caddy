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

package caddyscript

import (
	"fmt"
	"net/http"

	"github.com/starlight-go/starlight/convert"
	"go.starlark.net/starlark"
)

// HTTPRequest represents an http request type in caddyscript.
type HTTPRequest struct{ Req *http.Request }

// AttrNames defines what properties and methods are available on the HTTPRequest type.
func (r HTTPRequest) AttrNames() []string {
	return []string{"header", "query", "url", "method", "host", "tls", "redirect"}
}

func (r HTTPRequest) Freeze()               {}
func (r HTTPRequest) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: HTTPRequest") }
func (r HTTPRequest) String() string        { return fmt.Sprint(r.Req) }
func (r HTTPRequest) Type() string          { return "HTTPRequest" }
func (r HTTPRequest) Truth() starlark.Bool  { return true }

// Header handles returning a header key.
func (r HTTPRequest) Header(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var key string
	err := starlark.UnpackPositionalArgs(fn.Name(), args, kwargs, 1, &key)
	if err != nil {
		return starlark.None, fmt.Errorf("get request header: %v", err.Error())
	}

	return starlark.String(r.Req.Header.Get(key)), nil
}

// Redirect handles an http redirect from starlark code.
func (r HTTPRequest) Redirect(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var w starlark.Value
	var req HTTPRequest
	var newURL string
	err := starlark.UnpackPositionalArgs(fn.Name(), args, kwargs, 3, &w, &req, &newURL)
	if err != nil {
		return starlark.None, fmt.Errorf("unpacking arguments: %v", err.Error())
	}

	writer := convert.FromValue(w)
	if w, ok := writer.(http.ResponseWriter); ok {
		http.Redirect(w, req.Req, newURL, http.StatusSeeOther)
		return starlark.None, nil
	}

	return starlark.None, fmt.Errorf("first provided argument is not http.ResponseWriter")
}

// Attr defines what happens when props or methods are called on the HTTPRequest type.
func (r HTTPRequest) Attr(name string) (starlark.Value, error) {
	switch name {
	case "redirect":
		b := starlark.NewBuiltin("Redirect", r.Redirect)
		b = b.BindReceiver(r)

		return b, nil
	case "tls":
		tls := new(starlark.Dict)
		tls.SetKey(starlark.String("cipher_suite"), starlark.MakeUint(uint(r.Req.TLS.CipherSuite)))
		tls.SetKey(starlark.String("did_resume"), starlark.Bool(r.Req.TLS.DidResume))
		tls.SetKey(starlark.String("handshake_complete"), starlark.Bool(r.Req.TLS.HandshakeComplete))
		tls.SetKey(starlark.String("negotiated_protocol"), starlark.String(r.Req.TLS.NegotiatedProtocol))
		tls.SetKey(starlark.String("negotiated_protocol_is_mutual"), starlark.Bool(r.Req.TLS.NegotiatedProtocolIsMutual))
		tls.SetKey(starlark.String("server_name"), starlark.String(r.Req.TLS.ServerName))
		tls.SetKey(starlark.String("version"), starlark.String(r.Req.TLS.Version))

		return tls, nil
	case "header":
		b := starlark.NewBuiltin("Header", r.Header)
		b = b.BindReceiver(r)

		return b, nil
	case "query":
		qVals := r.Req.URL.Query()
		query := starlark.NewDict(len(qVals))

		for k, v := range qVals {
			query.SetKey(starlark.String(k), starlark.String(v[0]))
		}

		return query, nil
	case "url":
		return starlark.String(r.Req.URL.Path), nil
	case "method":
		return starlark.String(r.Req.Method), nil
	case "host":
		return starlark.String(r.Req.Host), nil
	}

	return nil, nil
}
