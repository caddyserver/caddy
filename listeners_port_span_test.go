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
	"strings"
	"testing"
)

// TestParseNetworkAddress_PortSpanBoundary is the regression test for
// the off-by-one in the port-range span check. A range like "0-65535"
// spans 65536 ports (inclusive on both ends) and should be rejected,
// but the old (end-start)>maxPortSpan check let it through. The maximum
// valid full-16-bit range "1-65535" (65535 ports) must still be accepted.
func TestParseNetworkAddress_PortSpanBoundary(t *testing.T) {
	for _, tt := range []struct {
		name    string
		addr    string
		wantErr bool
	}{
		{
			name:    "0-65535 spans 65536 ports and is rejected",
			addr:    "tcp/:0-65535",
			wantErr: true,
		},
		{
			name:    "1-65535 spans 65535 ports and is accepted",
			addr:    "tcp/:1-65535",
			wantErr: false,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseNetworkAddress(tt.addr)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !strings.Contains(err.Error(), "port range exceeds") {
					t.Errorf("expected 'port range exceeds' error, got: %v", err)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}
