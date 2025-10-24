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

	// Import to register global and http block types
	_ "github.com/caddyserver/caddy/v2/caddyconfig/blocktypes/globalblock"
	_ "github.com/caddyserver/caddy/v2/caddyconfig/blocktypes/httpblock"
)

func TestXCaddyfileBasic(t *testing.T) {
	input := `
[global] {
	admin off
}

[http] example.com {
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

func TestXCaddyfileRequiresBlockType(t *testing.T) {
	input := `
example.com {
	respond "Hello World"
}
`

	adapter := caddyfile.Adapter{ServerType: XCaddyfileType{}}

	_, _, err := adapter.Adapt([]byte(input), nil)
	if err == nil {
		t.Fatal("Expected error for missing block type, got nil")
	}

	if !strings.Contains(err.Error(), "block type declaration") {
		t.Errorf("Error should mention block type declaration requirement, got: %v", err)
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
}

[http] example.com {
	respond "Hello from HTTP"
}

[http] another.com {
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
