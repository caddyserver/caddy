// Copyright 2015 Light Code Labs, LLC
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

package timeouts

import (
	"testing"
	"time"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func TestSetupTimeouts(t *testing.T) {
	testCases := []struct {
		input     string
		shouldErr bool
	}{
		{input: "timeouts none", shouldErr: false},
		{input: "timeouts 5s", shouldErr: false},
		{input: "timeouts 0", shouldErr: false},
		{input: "timeouts { \n read 15s \n }", shouldErr: false},
		{input: "timeouts { \n read 15s \n idle 10s \n }", shouldErr: false},
		{input: "timeouts", shouldErr: true},
		{input: "timeouts 5s 10s", shouldErr: true},
		{input: "timeouts 12", shouldErr: true},
		{input: "timeouts -2s", shouldErr: true},
		{input: "timeouts { \n foo 1s \n }", shouldErr: true},
		{input: "timeouts { \n read \n }", shouldErr: true},
		{input: "timeouts { \n read 1s 2s \n }", shouldErr: true},
		{input: "timeouts { \n foo \n }", shouldErr: true},
	}
	for i, tc := range testCases {
		controller := caddy.NewTestController("", tc.input)
		err := setupTimeouts(controller)
		if tc.shouldErr && err == nil {
			t.Errorf("Test %d: Expected an error, but did not have one", i)
		}
		if !tc.shouldErr && err != nil {
			t.Errorf("Test %d: Did not expect error, but got: %v", i, err)
		}
	}
}

func TestTimeoutsSetProperly(t *testing.T) {
	testCases := []struct {
		input    string
		expected httpserver.Timeouts
	}{
		{
			input: "timeouts none",
			expected: httpserver.Timeouts{
				ReadTimeout: 0, ReadTimeoutSet: true,
				ReadHeaderTimeout: 0, ReadHeaderTimeoutSet: true,
				WriteTimeout: 0, WriteTimeoutSet: true,
				IdleTimeout: 0, IdleTimeoutSet: true,
			},
		},
		{
			input: "timeouts {\n read 15s \n}",
			expected: httpserver.Timeouts{
				ReadTimeout: 15 * time.Second, ReadTimeoutSet: true,
			},
		},
		{
			input: "timeouts {\n header 15s \n}",
			expected: httpserver.Timeouts{
				ReadHeaderTimeout: 15 * time.Second, ReadHeaderTimeoutSet: true,
			},
		},
		{
			input: "timeouts {\n write 15s \n}",
			expected: httpserver.Timeouts{
				WriteTimeout: 15 * time.Second, WriteTimeoutSet: true,
			},
		},
		{
			input: "timeouts {\n idle 15s \n}",
			expected: httpserver.Timeouts{
				IdleTimeout: 15 * time.Second, IdleTimeoutSet: true,
			},
		},
		{
			input: "timeouts {\n idle 15s \n read 1m \n }",
			expected: httpserver.Timeouts{
				IdleTimeout: 15 * time.Second, IdleTimeoutSet: true,
				ReadTimeout: 1 * time.Minute, ReadTimeoutSet: true,
			},
		},
		{
			input: "timeouts {\n read none \n }",
			expected: httpserver.Timeouts{
				ReadTimeout: 0, ReadTimeoutSet: true,
			},
		},
		{
			input: "timeouts {\n write 0 \n }",
			expected: httpserver.Timeouts{
				WriteTimeout: 0, WriteTimeoutSet: true,
			},
		},
		{
			input: "timeouts {\n write 1s \n write 2s \n }",
			expected: httpserver.Timeouts{
				WriteTimeout: 2 * time.Second, WriteTimeoutSet: true,
			},
		},
		{
			input: "timeouts 1s\ntimeouts 2s",
			expected: httpserver.Timeouts{
				ReadTimeout: 2 * time.Second, ReadTimeoutSet: true,
				ReadHeaderTimeout: 2 * time.Second, ReadHeaderTimeoutSet: true,
				WriteTimeout: 2 * time.Second, WriteTimeoutSet: true,
				IdleTimeout: 2 * time.Second, IdleTimeoutSet: true,
			},
		},
	}
	for i, tc := range testCases {
		controller := caddy.NewTestController("", tc.input)
		err := setupTimeouts(controller)
		if err != nil {
			t.Fatalf("Test %d: Did not expect error, but got: %v", i, err)
		}
		cfg := httpserver.GetConfig(controller)
		if got, want := cfg.Timeouts.ReadTimeout, tc.expected.ReadTimeout; got != want {
			t.Errorf("Test %d: Expected ReadTimeout=%v, got %v", i, want, got)
		}
		if got, want := cfg.Timeouts.ReadTimeoutSet, tc.expected.ReadTimeoutSet; got != want {
			t.Errorf("Test %d: Expected ReadTimeoutSet=%v, got %v", i, want, got)
		}
		if got, want := cfg.Timeouts.ReadHeaderTimeout, tc.expected.ReadHeaderTimeout; got != want {
			t.Errorf("Test %d: Expected ReadHeaderTimeout=%v, got %v", i, want, got)
		}
		if got, want := cfg.Timeouts.ReadHeaderTimeoutSet, tc.expected.ReadHeaderTimeoutSet; got != want {
			t.Errorf("Test %d: Expected ReadHeaderTimeoutSet=%v, got %v", i, want, got)
		}
		if got, want := cfg.Timeouts.WriteTimeout, tc.expected.WriteTimeout; got != want {
			t.Errorf("Test %d: Expected WriteTimeout=%v, got %v", i, want, got)
		}
		if got, want := cfg.Timeouts.WriteTimeoutSet, tc.expected.WriteTimeoutSet; got != want {
			t.Errorf("Test %d: Expected WriteTimeoutSet=%v, got %v", i, want, got)
		}
		if got, want := cfg.Timeouts.IdleTimeout, tc.expected.IdleTimeout; got != want {
			t.Errorf("Test %d: Expected IdleTimeout=%v, got %v", i, want, got)
		}
		if got, want := cfg.Timeouts.IdleTimeoutSet, tc.expected.IdleTimeoutSet; got != want {
			t.Errorf("Test %d: Expected IdleTimeoutSet=%v, got %v", i, want, got)
		}
	}
}
