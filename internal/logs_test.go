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

package internal

import "testing"

// TestMaxSizeSubjectsListForLog_MaxIsZero is the regression test for
// the off-by-one where a domain leaked into the output when maxToDisplay
// was 0.
func TestMaxSizeSubjectsListForLog_MaxIsZero(t *testing.T) {
	subjects := map[string]struct{}{
		"a.com": {},
		"b.com": {},
	}
	got := MaxSizeSubjectsListForLog(subjects, 0)
	if len(got) != 1 {
		t.Fatalf("expected only the suffix entry, got %d items: %v", len(got), got)
	}
	if len(got[0]) < 4 || got[0][:4] != "(and" {
		t.Errorf("expected the only entry to be the '(and N more...)' suffix, got %q", got[0])
	}
}
