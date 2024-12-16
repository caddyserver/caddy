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
	"testing"
	"time"
)

func TestParseDuration(t *testing.T) {
	const day = 24 * time.Hour
	for i, tc := range []struct {
		input  string
		expect time.Duration
	}{
		{
			input:  "3h",
			expect: 3 * time.Hour,
		},
		{
			input:  "1d",
			expect: day,
		},
		{
			input:  "1d30m",
			expect: day + 30*time.Minute,
		},
		{
			input:  "1m2d",
			expect: time.Minute + day*2,
		},
		{
			input:  "1m2d30s",
			expect: time.Minute + day*2 + 30*time.Second,
		},
		{
			input:  "1d2d",
			expect: 3 * day,
		},
		{
			input:  "1.5d",
			expect: time.Duration(1.5 * float64(day)),
		},
		{
			input:  "4m1.25d",
			expect: 4*time.Minute + time.Duration(1.25*float64(day)),
		},
		{
			input:  "-1.25d12h",
			expect: time.Duration(-1.25*float64(day)) - 12*time.Hour,
		},
	} {
		actual, err := ParseDuration(tc.input)
		if err != nil {
			t.Errorf("Test %d ('%s'): Got error: %v", i, tc.input, err)
			continue
		}
		if actual != tc.expect {
			t.Errorf("Test %d ('%s'): Expected=%s Actual=%s", i, tc.input, tc.expect, actual)
		}
	}
}
