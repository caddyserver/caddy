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

package reverseproxy

import (
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestUnmarshalCaddyfileRejectsH2CWithTLS(t *testing.T) {
	const wantErr = "cannot use TLS options with h2c:// upstreams"

	tests := []struct {
		name    string
		input   string
		wantErr string
	}{
		{
			name: "h2c with tls_insecure_skip_verify",
			input: `reverse_proxy h2c://localhost:3000 {
				transport http {
					tls_insecure_skip_verify
				}
			}`,
			wantErr: wantErr,
		},
		{
			name: "h2c with tls",
			input: `reverse_proxy h2c://localhost:3000 {
				transport http {
					tls
				}
			}`,
			wantErr: wantErr,
		},
		{
			name: "h2c with tls_server_name",
			input: `reverse_proxy h2c://localhost:3000 {
				transport http {
					tls_server_name example.com
				}
			}`,
			wantErr: wantErr,
		},
		{
			name: "h2c without TLS options",
			input: `reverse_proxy h2c://localhost:3000 {
				transport http {
					versions h2c
				}
			}`,
		},
		{
			name: "https with tls_insecure_skip_verify",
			input: `reverse_proxy https://localhost:3000 {
				transport http {
					tls_insecure_skip_verify
				}
			}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := &Handler{}
			d := caddyfile.NewTestDispenser(tc.input)
			err := h.UnmarshalCaddyfile(d)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}
