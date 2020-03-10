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

package jsoncadapter

import (
	"encoding/json"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/muhammadmuzzammil1998/jsonc"
)

func init() {
	caddy.RegisterModule(Adapter{})
}

// Adapter adapts JSON-C to Caddy JSON.
type Adapter struct{}

func (_ Adapter) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "adapters.jsonc",
		New: func() caddy.Module {
			return Adapter{}
		},
	}
}

// Adapt converts the JSON-C config in body to Caddy JSON.
func (a Adapter) Adapt(body []byte, options map[string]interface{}) (result []byte, warnings []caddyconfig.Warning, err error) {
	result = jsonc.ToJSON(body)

	// any errors in the JSON will be
	// reported during config load, but
	// we can at least warn here that
	// it is not valid JSON
	if !json.Valid(result) {
		warnings = append(warnings, caddyconfig.Warning{
			Message: "Resulting JSON is invalid.",
		})
	}

	return
}

// Interface guard
var _ caddyconfig.Adapter = (*Adapter)(nil)
