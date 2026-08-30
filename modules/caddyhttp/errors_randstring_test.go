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

package caddyhttp

import (
	"strings"
	"testing"
)

// TestRandString_SameCaseExcludesZero is the regression test for the
// randString(sameCase=true) dictionary bug where '0' was still emitted
// despite being called out as a confusing character in the doc comment.
func TestRandString_SameCaseExcludesZero(t *testing.T) {
	// A sample of 5000 characters makes a leaked '0' extremely unlikely
	// to go unnoticed: the dictionary is 33 characters, so the expected
	// count for any single character would be ~151 if it were present.
	s := randString(5000, true)
	if strings.ContainsRune(s, '0') {
		t.Errorf("randString(n, sameCase=true) must not emit '0'; got %q", s)
	}
}
