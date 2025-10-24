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

package xcaddyfile

import (
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"

	// Import to register global and http.server block types
	_ "github.com/caddyserver/caddy/v2/caddyconfig/xcaddyfile/blocktypes/globalblock"
	_ "github.com/caddyserver/caddy/v2/caddyconfig/xcaddyfile/blocktypes/httpserverblock"
)

func TestXCaddyfileBasic(t *testing.T) {
	input := `
[global] {
	admin off
}

[http.server] example.com {
	respond "Hello World"
}
`

	adapter := caddyfile.Adapter{ServerType: XCaddyfileType{}}

	_, warnings, err := adapter.Adapt([]byte(input), nil)
	if err != nil {
		t.Fatalf("Adapt() error = %v", err)
	}

	if len(warnings) > 0 {
		t.Logf("Warnings: %v", warnings)
	}
}

func TestXCaddyfileBackwardsCompatibility(t *testing.T) {
	// Test that standard Caddyfile syntax works (implicit http.server)
	input := `
example.com {
	respond "Hello World"
}
`

	adapter := caddyfile.Adapter{ServerType: XCaddyfileType{}}

	_, warnings, err := adapter.Adapt([]byte(input), nil)
	if err != nil {
		t.Fatalf("Adapt() should work with standard Caddyfile syntax, error = %v", err)
	}

	if len(warnings) > 0 {
		t.Logf("Warnings: %v", warnings)
	}
}

func TestXCaddyfileBackwardsCompatibilityGlobalBlock(t *testing.T) {
	// Test that anonymous first block is treated as global
	input := `
{
	admin off
	grace_period 30s
}

example.com {
	respond "Hello World"
}
`

	adapter := caddyfile.Adapter{ServerType: XCaddyfileType{}}

	_, warnings, err := adapter.Adapt([]byte(input), nil)
	if err != nil {
		t.Fatalf("Adapt() should work with standard Caddyfile global block, error = %v", err)
	}

	if len(warnings) > 0 {
		t.Logf("Warnings: %v", warnings)
	}
}

func TestXCaddyfileUnknownBlockType(t *testing.T) {
	input := `
[unknown] {
	some directive
}
`

	adapter := caddyfile.Adapter{ServerType: XCaddyfileType{}}

	_, _, err := adapter.Adapt([]byte(input), nil)
	if err == nil {
		t.Fatal("Expected error for unknown block type, got nil")
	}

	if !strings.Contains(err.Error(), "not registered") {
		t.Errorf("Error should mention unregistered block type, got: %v", err)
	}
}

func TestXCaddyfileMultipleBlockTypes(t *testing.T) {
	input := `
[global] {
	admin off
	grace_period 30s
}

[http.server] example.com {
	respond "Hello from HTTP"
}

[http.server] another.com {
	respond "Hello from another"
}
`

	adapter := caddyfile.Adapter{ServerType: XCaddyfileType{}}

	_, warnings, err := adapter.Adapt([]byte(input), nil)
	if err != nil {
		t.Fatalf("Adapt() error = %v", err)
	}

	if len(warnings) > 0 {
		t.Logf("Warnings: %v", warnings)
	}
}
