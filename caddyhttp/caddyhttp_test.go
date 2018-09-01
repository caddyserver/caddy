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

package caddyhttp

import (
	"strings"
	"testing"

	"github.com/mholt/caddy"
)

// TODO: this test could be improved; the purpose is to
// ensure that the standard plugins are in fact plugged in
// and registered properly; this is a quick/naive way to do it.
func TestStandardPlugins(t *testing.T) {
	numStandardPlugins := 31 // importing caddyhttp plugs in this many plugins
	s := caddy.DescribePlugins()
	if got, want := strings.Count(s, "\n"), numStandardPlugins+5; got != want {
		t.Errorf("Expected all standard plugins to be plugged in, got:\n%s", s)
	}
}
