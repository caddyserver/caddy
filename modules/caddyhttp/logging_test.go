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
	"slices"
	"testing"
)

func TestServerLogConfigLoggerNamesCaseInsensitive(t *testing.T) {
	slc := ServerLogConfig{
		DefaultLoggerName: "default",
		LoggerNames: map[string]StringArray{
			"example.com":       {"exact"},
			"Mixed.Example.org": {"mixed"},
			"*.EXAMPLE.net":     {"wildcard"},
			"foo.example.dev":   {"lower"},
			"FOO.example.dev":   {"upper", "lower"},
			"muted.example.com": {},
		},
	}
	slc.normalizeLoggerNames()

	for i, tc := range []struct {
		host     string
		expected []string
	}{
		{host: "EXAMPLE.COM", expected: []string{"exact"}},
		{host: "mixed.example.org", expected: []string{"mixed"}},
		{host: "Sub.example.NET", expected: []string{"wildcard"}},
		// merged in sorted key order; "FOO..." sorts before "foo..."
		{host: "foo.example.dev", expected: []string{"upper", "lower"}},
		// mapped to no loggers, so no fallback to the default logger,
		// an empty mapping can only come from a JSON config
		{host: "MUTED.example.com", expected: []string{}},
	} {
		actual := slc.getLoggerHosts(tc.host)
		if !slices.Equal(actual, tc.expected) {
			t.Errorf("Test %d (%s): expected %v, got %v", i, tc.host, tc.expected, actual)
		}
	}
}
