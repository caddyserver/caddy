package caddyscript

import (
	"fmt"
	"net/http"

	"go.starlark.net/starlark"
)

// HTTPRequest represents an http request type in caddyscript.
type HTTPRequest struct{ Req *http.Request }

// AttrNames defines what properties and methods are available on the HTTPRequest type.
func (r HTTPRequest) AttrNames() []string {
	return []string{"header", "query", "url", "method", "host", "tls"}
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

// Attr defines what happens when props or methods are called on the HTTPRequest type.
func (r HTTPRequest) Attr(name string) (starlark.Value, error) {
	switch name {
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
