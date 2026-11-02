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

// TestRandString_NotSameCaseExcludedChars is the regression test for the
// randString(sameCase=false) dictionary bug where excluded was still emitted
// despite being called out as a confusing character in the doc comment.
func TestRandString_NotSameCaseExcludedChars(t *testing.T) {
	// A sample of 5000 characters makes a leaked excluded character extremely unlikely
	// to go unnoticed: the dictionary is 55 characters, so the expected
	// count for any single character would be ~90 if it were present.
	s := randString(5000, false)
	if strings.ContainsRune(s, 'l') {
		t.Errorf("randString(n, sameCase=false) must not emit 'l'; got %q", s)
	}
	if strings.ContainsRune(s, 'I') {
		t.Errorf("randString(n, sameCase=false) must not emit 'I'; got %q", s)
	}
	if strings.ContainsRune(s, 'O') {
		t.Errorf("randString(n, sameCase=false) must not emit 'O'; got %q", s)
	}
	if strings.ContainsRune(s, 'S') {
		t.Errorf("randString(n, sameCase=false) must not emit 'S'; got %q", s)
	}
	if strings.ContainsRune(s, '0') {
		t.Errorf("randString(n, sameCase=false) must not emit '0'; got %q", s)
	}
	if strings.ContainsRune(s, '1') {
		t.Errorf("randString(n, sameCase=false) must not emit '1'; got %q", s)
	}
}

// TestRandString_SameCaseExcludedChars is the regression test for the
// randString(sameCase=true) dictionary bug where excluded was still emitted
// despite being called out as a confusing character in the doc comment.
func TestRandString_SameCaseExcludedChars(t *testing.T) {
	// A sample of 5000 characters makes a leaked excluded character extremely unlikely
	// to go unnoticed: the dictionary is 32 characters, so the expected
	// count for any single character would be ~156 if it were present.
	s := randString(5000, true)
	if strings.ToLower(s) != s {
		t.Errorf("randString(n, sameCase=true) must not emit uppercase letters; got %q", s)
	}
	if strings.ContainsRune(s, 'l') {
		t.Errorf("randString(n, sameCase=true) must not emit 'l'; got %q", s)
	}
	if strings.ContainsRune(s, 'o') {
		t.Errorf("randString(n, sameCase=true) must not emit 'o': got %q", s)
	}
	if strings.ContainsRune(s, '0') {
		t.Errorf("randString(n, sameCase=true) must not emit '0'; got %q", s)
	}
	if strings.ContainsRune(s, '1') {
		t.Errorf("randString(n, sameCase=true) must not emit '1'; got %q", s)
	}
}
