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

package httpcaddyfile

import (
	"encoding/json"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// defaultDirectiveOrder specifies the order
// to apply directives in HTTP routes.
var defaultDirectiveOrder = []string{
	"rewrite",
	"try_files",
	"headers",
	"request_header",
	"encode",
	"templates",
	"redir",
	"respond",
	"reverse_proxy",
	"php_fastcgi",
	"file_server",
}

// RegisterDirective registers a unique directive dir with an
// associated unmarshaling (setup) function. When directive dir
// is encountered in a Caddyfile, setupFunc will be called to
// unmarshal its tokens.
func RegisterDirective(dir string, setupFunc UnmarshalFunc) {
	if _, ok := registeredDirectives[dir]; ok {
		panic("directive " + dir + " already registered")
	}
	registeredDirectives[dir] = setupFunc
}

// RegisterHandlerDirective is like RegisterDirective, but for
// directives which specifically output only an HTTP handler.
func RegisterHandlerDirective(dir string, setupFunc UnmarshalHandlerFunc) {
	RegisterDirective(dir, func(h Helper) ([]ConfigValue, error) {
		if !h.Next() {
			return nil, h.ArgErr()
		}

		matcherSet, ok, err := h.MatcherToken()
		if err != nil {
			return nil, err
		}
		if ok {
			h.Dispenser.Delete() // strip matcher token
		}

		h.Dispenser.Reset() // pretend this lookahead never happened
		val, err := setupFunc(h)
		if err != nil {
			return nil, err
		}

		return h.NewRoute(matcherSet, val), nil
	})
}

// Helper is a type which helps setup a value from
// Caddyfile tokens.
type Helper struct {
	*caddyfile.Dispenser
	options     map[string]interface{}
	warnings    *[]caddyconfig.Warning
	matcherDefs map[string]map[string]json.RawMessage
	parentBlock caddyfile.ServerBlock
}

// Option gets the option keyed by name.
func (h Helper) Option(name string) interface{} {
	return h.options[name]
}

// Caddyfiles returns the list of config files from
// which tokens in the current server block were loaded.
func (h Helper) Caddyfiles() []string {
	// first obtain set of names of files involved
	// in this server block, without duplicates
	files := make(map[string]struct{})
	for _, segment := range h.parentBlock.Segments {
		for _, token := range segment {
			files[token.File] = struct{}{}
		}
	}
	// then convert the set into a slice
	filesSlice := make([]string, 0, len(files))
	for file := range files {
		filesSlice = append(filesSlice, file)
	}
	return filesSlice
}

// JSON converts val into JSON. Any errors are added to warnings.
func (h Helper) JSON(val interface{}, warnings *[]caddyconfig.Warning) json.RawMessage {
	return caddyconfig.JSON(val, h.warnings)
}

// MatcherToken assumes the current token is (possibly) a matcher, and
// if so, returns the matcher set along with a true value. If the current
// token is not a matcher, nil and false is returned. Note that a true
// value may be returned with a nil matcher set if it is a catch-all.
func (h Helper) MatcherToken() (map[string]json.RawMessage, bool, error) {
	if !h.NextArg() {
		return nil, false, nil
	}
	return matcherSetFromMatcherToken(h.Dispenser.Token(), h.matcherDefs, h.warnings)
}

// NewRoute returns config values relevant to creating a new HTTP route.
func (h Helper) NewRoute(matcherSet map[string]json.RawMessage,
	handler caddyhttp.MiddlewareHandler) []ConfigValue {
	mod, err := caddy.GetModule(caddy.GetModuleName(handler))
	if err != nil {
		// TODO: append to warnings
	}
	var matcherSetsRaw []map[string]json.RawMessage
	if matcherSet != nil {
		matcherSetsRaw = append(matcherSetsRaw, matcherSet)
	}
	return []ConfigValue{
		{
			Class: "route",
			Value: caddyhttp.Route{
				MatcherSetsRaw: matcherSetsRaw,
				HandlersRaw:    []json.RawMessage{caddyconfig.JSONModuleObject(handler, "handler", mod.ID(), h.warnings)},
			},
		},
	}
}

// NewBindAddresses returns config values relevant to adding
// listener bind addresses to the config.
func (h Helper) NewBindAddresses(addrs []string) []ConfigValue {
	return []ConfigValue{{Class: "bind", Value: addrs}}
}

// NewVarsRoute returns config values relevant to adding a
// "vars" wrapper route to the config.
func (h Helper) NewVarsRoute(route caddyhttp.Route) []ConfigValue {
	return []ConfigValue{{Class: "var", Value: route}}
}

// ConfigValue represents a value to be added to the final
// configuration, or a value to be consulted when building
// the final configuration.
type ConfigValue struct {
	// The kind of value this is. As the config is
	// being built, the adapter will look in the
	// "pile" for values belonging to a certain
	// class when it is setting up a certain part
	// of the config. The associated value will be
	// type-asserted and placed accordingly.
	Class string

	// The value to be used when building the config.
	// Generally its type is associated with the
	// name of the Class.
	Value interface{}

	directive string
}

// serverBlock pairs a Caddyfile server block
// with a "pile" of config values, keyed by class
// name.
type serverBlock struct {
	block caddyfile.ServerBlock
	pile  map[string][]ConfigValue // config values obtained from directives
}

type (
	// UnmarshalFunc is a function which can unmarshal Caddyfile
	// tokens into zero or more config values using a Helper type.
	// These are passed in a call to RegisterDirective.
	UnmarshalFunc func(h Helper) ([]ConfigValue, error)

	// UnmarshalHandlerFunc is like UnmarshalFunc, except the
	// output of the unmarshaling is an HTTP handler. This
	// function does not need to deal with HTTP request matching
	// which is abstracted away. Since writing HTTP handlers
	// with Caddyfile support is very common, this is a more
	// convenient way to add a handler to the chain since a lot
	// of the details common to HTTP handlers are taken care of
	// for you. These are passed to a call to
	// RegisterHandlerDirective.
	UnmarshalHandlerFunc func(h Helper) (caddyhttp.MiddlewareHandler, error)
)

var registeredDirectives = make(map[string]UnmarshalFunc)
