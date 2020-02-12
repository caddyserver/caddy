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
	"testing"

	caddyfile "github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestParse(t *testing.T) {

	for i, tc := range []struct {
		input       string
		expectWarn  bool
		expectError bool
	}{
		{
			input: `http://localhost
			@debug {
			  query showdebug=1
			}
			`,
			expectWarn:  false,
			expectError: false,
		},
		{
			input: `http://localhost
			@debug {
			  query bad format
			}
			`,
			expectWarn:  false,
			expectError: true,
		},
		{
			input: `
			{
				email test@anon.com
				acme_ca https://ca.custom
				acme_ca_root /root/certs/ca.crt
			}

			https://caddy {
				tls {
					ca https://ca.custom
					ca_root /root/certs/ca.crt
				}
			}
			`,
			expectWarn:  false,
			expectError: false,
		},
	} {

		adapter := caddyfile.Adapter{
			ServerType: ServerType{},
		}

		_, warnings, err := adapter.Adapt([]byte(tc.input), nil)

		if len(warnings) > 0 != tc.expectWarn {
			t.Errorf("Test %d warning expectation failed Expected: %v, got %v", i, tc.expectWarn, warnings)
			continue
		}

		if err != nil != tc.expectError {
			t.Errorf("Test %d error expectation failed Expected: %v, got %s", i, tc.expectError, err)
			continue
		}
	}
}
