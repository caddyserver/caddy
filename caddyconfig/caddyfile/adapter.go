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

package caddyfile

import (
	"encoding/json"
	"fmt"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
)

func init() {
	caddy.RegisterModule(Adapter{})
}

// Adapter adapts Caddyfile to Caddy JSON.
type Adapter struct {
	ServerType ServerType
}

func (_ Adapter) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "adapters.caddyfile",
		New: func() caddy.Module {
			return Adapter{}
		},
	}
}

// Adapt converts the Caddyfile config in body to Caddy JSON.
func (a Adapter) Adapt(body []byte, options map[string]interface{}) ([]byte, []caddyconfig.Warning, error) {
	if a.ServerType == nil {
		return nil, nil, fmt.Errorf("no server type")
	}
	if options == nil {
		options = make(map[string]interface{})
	}

	filename, _ := options["filename"].(string)
	if filename == "" {
		filename = "Caddyfile"
	}

	serverBlocks, err := Parse(filename, body)
	if err != nil {
		return nil, nil, err
	}

	cfg, warnings, err := a.ServerType.Setup(serverBlocks, options)
	if err != nil {
		return nil, warnings, err
	}

	marshalFunc := json.Marshal
	if options["pretty"] == "true" {
		marshalFunc = caddyconfig.JSONIndent
	}
	result, err := marshalFunc(cfg)

	return result, warnings, err
}

// Unmarshaler is a type that can unmarshal
// Caddyfile tokens to set itself up for a
// JSON encoding. The goal of an unmarshaler
// is not to set itself up for actual use,
// but to set itself up for being marshaled
// into JSON. Caddyfile-unmarshaled values
// will not be used directly; they will be
// encoded as JSON and then used from that.
type Unmarshaler interface {
	UnmarshalCaddyfile(d *Dispenser) error
}

// ServerType is a type that can evaluate a Caddyfile and set up a caddy config.
type ServerType interface {
	// Setup takes the server blocks which
	// contain tokens, as well as options
	// (e.g. CLI flags) and creates a Caddy
	// config, along with any warnings or
	// an error.
	Setup([]ServerBlock, map[string]interface{}) (*caddy.Config, []caddyconfig.Warning, error)
}

// Interface guard
var _ caddyconfig.Adapter = (*Adapter)(nil)
