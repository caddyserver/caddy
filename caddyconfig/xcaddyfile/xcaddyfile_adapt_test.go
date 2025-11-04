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
	"bytes"
	"encoding/json"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"

	// Import to register global and http.server block types
	_ "github.com/caddyserver/caddy/v2/caddyconfig/xcaddyfile/blocktypes/globalblock"
	_ "github.com/caddyserver/caddy/v2/caddyconfig/xcaddyfile/blocktypes/httpserverblock"
)

// TestXCaddyfileBackwardsCompatibilityWithCaddyfile ensures that xcaddyfile
// produces the same output as the standard caddyfile adapter when processing
// standard Caddyfile syntax (without explicit [type] declarations).
func TestXCaddyfileBackwardsCompatibilityWithCaddyfile(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name: "simple site",
			input: `
example.com {
	respond "Hello World"
}
`,
		},
		{
			name: "multiple sites",
			input: `
example.com {
	respond "Hello from example"
}

another.com {
	respond "Hello from another"
}
`,
		},
		{
			name: "global block with sites",
			input: `
{
	admin off
	grace_period 30s
}

example.com {
	file_server
}
`,
		},
		{
			name: "site with directives",
			input: `
example.com {
	root * /var/www
	file_server
	encode gzip
}
`,
		},
		{
			name: "reverse proxy",
			input: `
api.example.com {
	reverse_proxy localhost:9000
}
`,
		},
		{
			name: "global options",
			input: `
{
	https_port 8443
	http_port 8080
	grace_period 10s
}

example.com {
	respond "OK"
}
`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Parse with standard caddyfile adapter
			caddyfileAdapter := caddyfile.Adapter{ServerType: httpcaddyfile.ServerType{}}
			caddyfileCfg, caddyfileWarnings, caddyfileErr := caddyfileAdapter.Adapt([]byte(tc.input), nil)

			// Parse with xcaddyfile adapter
			xcaddyfileAdapter := caddyfile.Adapter{ServerType: XCaddyfileType{}}
			xcaddyfileCfg, xcaddyfileWarnings, xcaddyfileErr := xcaddyfileAdapter.Adapt([]byte(tc.input), nil)

			// Both should succeed or both should fail
			if (caddyfileErr == nil) != (xcaddyfileErr == nil) {
				t.Fatalf("Error mismatch:\n  caddyfile error: %v\n  xcaddyfile error: %v", caddyfileErr, xcaddyfileErr)
			}

			// If both errored, we're done
			if caddyfileErr != nil {
				return
			}

			// Compare warnings count (they might differ slightly in content)
			if len(caddyfileWarnings) != len(xcaddyfileWarnings) {
				t.Logf("Warning count differs: caddyfile=%d, xcaddyfile=%d", len(caddyfileWarnings), len(xcaddyfileWarnings))
			}

			// Normalize both JSON configs for comparison (prettify)
			var caddyfileBuf, xcaddyfileBuf bytes.Buffer
			if err := json.Indent(&caddyfileBuf, caddyfileCfg, "", "  "); err != nil {
				t.Fatalf("Failed to indent caddyfile config: %v", err)
			}
			if err := json.Indent(&xcaddyfileBuf, xcaddyfileCfg, "", "  "); err != nil {
				t.Fatalf("Failed to indent xcaddyfile config: %v", err)
			}

			if caddyfileBuf.String() != xcaddyfileBuf.String() {
				t.Errorf("Config mismatch:\n\nCaddyfile output:\n%s\n\nXCaddyfile output:\n%s",
					caddyfileBuf.String(), xcaddyfileBuf.String())
			}
		})
	}
}
