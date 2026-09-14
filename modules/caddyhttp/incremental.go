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
	"net/http"

	"github.com/dunglas/httpsfv"
)

// incrementalHeader is the HTTP field with which a sender asks intermediaries
// to start forwarding a message before it has been received in full.
// See RFC 10036: https://www.rfc-editor.org/rfc/rfc10036.html
const incrementalHeader = "Incremental"

// IsIncremental returns true if hdr requests incremental forwarding of the
// message it belongs to. The field applies to a single message, so a
// request and its response have to carry it independently.
func IsIncremental(hdr http.Header) bool {
	vals := hdr.Values(incrementalHeader)
	if len(vals) == 0 {
		return false
	}

	// every sender serializes true this way, and parsing it costs
	// ~3x more time and two allocations
	if len(vals) == 1 && vals[0] == "?1" {
		return true
	}

	item, err := httpsfv.UnmarshalItem(vals)
	if err != nil {
		return false
	}

	// only a Boolean is valid; any other type is ignored, as are
	// parameters we don't know about
	b, ok := item.Value.(bool)

	return ok && b
}
