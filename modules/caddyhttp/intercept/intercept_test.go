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

package intercept

import (
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestInterceptUnmarshalCaddyfile(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		wantErrSub   string
		wantHandlers int
		verify       func(t *testing.T, i *Intercept)
	}{
		{
			name: "replace_status with single status code arg",
			input: `intercept {
				replace_status 404
			}`,
			wantHandlers: 1,
			verify: func(t *testing.T, i *Intercept) {
				rh := i.HandleResponse[0]
				if got := rh.StatusCode.String(); got != "404" {
					t.Errorf("StatusCode: got %q, want %q", got, "404")
				}
				if rh.Match != nil {
					t.Errorf("Match should be nil when no matcher given, got %+v", rh.Match)
				}
			},
		},
		{
			name: "replace_status with named matcher",
			input: `intercept {
				@nf status 404
				replace_status @nf 500
			}`,
			wantHandlers: 1,
			verify: func(t *testing.T, i *Intercept) {
				rh := i.HandleResponse[0]
				if got := rh.StatusCode.String(); got != "500" {
					t.Errorf("StatusCode: got %q, want %q", got, "500")
				}
				if rh.Match == nil {
					t.Fatal("Match should be set when named matcher referenced")
				}
				if len(rh.Match.StatusCode) != 1 || rh.Match.StatusCode[0] != 404 {
					t.Errorf("Match.StatusCode: got %v, want [404]", rh.Match.StatusCode)
				}
			},
		},
		{
			name: "multiple replace_status entries are collected in order",
			input: `intercept {
				@nf status 404
				@srv status 5xx
				replace_status @nf 410
				replace_status 200
				replace_status @srv 503
			}`,
			wantHandlers: 3,
			verify: func(t *testing.T, i *Intercept) {
				if got := i.HandleResponse[0].StatusCode.String(); got != "410" {
					t.Errorf("HandleResponse[0].StatusCode: got %q, want %q", got, "410")
				}
				if i.HandleResponse[0].Match == nil {
					t.Errorf("HandleResponse[0].Match should be set")
				}
				if got := i.HandleResponse[1].StatusCode.String(); got != "200" {
					t.Errorf("HandleResponse[1].StatusCode: got %q, want %q", got, "200")
				}
				if i.HandleResponse[1].Match != nil {
					t.Errorf("HandleResponse[1].Match should be nil")
				}
				if got := i.HandleResponse[2].StatusCode.String(); got != "503" {
					t.Errorf("HandleResponse[2].StatusCode: got %q, want %q", got, "503")
				}
			},
		},
		{
			name: "replace_status with no arguments errors",
			input: `intercept {
				replace_status
			}`,
			wantErrSub: "must have one or two arguments",
		},
		{
			name: "replace_status with three arguments errors",
			input: `intercept {
				@nf status 404
				replace_status @nf 500 extra
			}`,
			wantErrSub: "must have one or two arguments",
		},
		{
			name: "replace_status with two args but first is not a matcher errors",
			input: `intercept {
				replace_status foo 500
			}`,
			wantErrSub: "must use a named response matcher",
		},
		{
			name: "replace_status with undefined named matcher errors",
			input: `intercept {
				replace_status @undefined 500
			}`,
			wantErrSub: "no named response matcher defined with name 'undefined'",
		},
		{
			name: "replace_status with block errors",
			input: `intercept {
				replace_status 500 {
					foo bar
				}
			}`,
			wantErrSub: "cannot define routes for 'replace_status'",
		},
		{
			name: "unrecognized subdirective errors",
			input: `intercept {
				bogus 1
			}`,
			wantErrSub: "unrecognized subdirective bogus",
		},
		{
			name: "matcher with no body parses without error and adds no handlers",
			input: `intercept {
				@nf status 404
			}`,
			wantHandlers: 0,
			verify: func(t *testing.T, i *Intercept) {
				if _, ok := i.responseMatchers["@nf"]; !ok {
					t.Errorf("expected @nf matcher to be registered, got %v", i.responseMatchers)
				}
			},
		},
		{
			name: "duplicate named matcher errors",
			input: `intercept {
				@nf status 404
				@nf status 500
			}`,
			wantErrSub: "matcher is defined more than once",
		},
		{
			name: "empty intercept block parses successfully",
			input: `intercept {
			}`,
			wantHandlers: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(tc.input)
			i := &Intercept{}
			err := i.UnmarshalCaddyfile(d)

			if tc.wantErrSub != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.wantErrSub)
				}
				if !strings.Contains(err.Error(), tc.wantErrSub) {
					t.Errorf("error %q does not contain %q", err.Error(), tc.wantErrSub)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(i.HandleResponse) != tc.wantHandlers {
				t.Errorf("HandleResponse count: got %d, want %d", len(i.HandleResponse), tc.wantHandlers)
			}
			if tc.verify != nil {
				tc.verify(t, i)
			}
		})
	}
}
