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
	"errors"
	"testing"
)

func TestWithBindCapabilityPassthrough(t *testing.T) {
	before, err := shouldRaiseBindCapability()
	if err != nil {
		t.Fatalf("reading capabilities: %v", err)
	}

	sentinel := errors.New("sentinel")
	for _, na := range []NetworkAddress{
		{Network: "tcp", Host: "localhost", StartPort: 80, EndPort: 80},
		{Network: "udp", Host: "localhost", StartPort: 8080, EndPort: 8080},
		{Network: "unix", Host: "/tmp/caddy.sock"},
	} {
		ln, err := na.withBindCapability(0, func() (any, error) {
			return "listener", sentinel
		})
		if ln != "listener" || !errors.Is(err, sentinel) {
			t.Errorf("%s: got (%v, %v), want listen's return values", na, ln, err)
		}
	}

	after, err := shouldRaiseBindCapability()
	if err != nil {
		t.Fatalf("reading capabilities: %v", err)
	}
	if before != after {
		t.Errorf("capabilities of calling thread changed")
	}
}
