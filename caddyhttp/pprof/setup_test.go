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

package pprof

import (
	"testing"

	"github.com/caddyserver/caddy"
)

func TestSetup(t *testing.T) {
	tests := []struct {
		input     string
		shouldErr bool
	}{
		{`pprof`, false},
		{`pprof {}`, true},
		{`pprof /foo`, true},
		{`pprof {
            a b
        }`, true},
		{`pprof
          pprof`, true},
	}
	for i, test := range tests {
		c := caddy.NewTestController("http", test.input)
		err := setup(c)
		if test.shouldErr && err == nil {
			t.Errorf("Test %v: Expected error but found nil", i)
		} else if !test.shouldErr && err != nil {
			t.Errorf("Test %v: Expected no error but found error: %v", i, err)
		}
	}
}
