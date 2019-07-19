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
)

func fakeReplacer() replacer {
	return replacer{
		providers: make([]ReplacementFunc, 0),
		static:    make(map[string]string),
	}
}

func fakeReplacerFilled() replacer {
	return replacer{
		providers: []ReplacementFunc{
			// split our possible vars to two functions (to test if both functions are called)
			func(key string) (val string, ok bool) {
				switch key {
				case "test1":
					return "val1", true
				case "asdf":
					return "123", true
				case "äöü":
					return "öö_äü", true
				case "with space":
					return "space value", true
				default:
					return "NOOO", false
				}
			},
			func(key string) (val string, ok bool) {
				switch key {
				case "1":
					return "test-123", true
				case "mySuper_IP":
					return "1.2.3.4", true
				case "testEmpty":
					return "", true
				default:
					return "NOOO", false
				}
			},
		},
	}
}

func fakeReplacerFilledStatic() replacer {
	return replacer{
		static: map[string]string{
			"key1": "val1",
			"key2": "val2",
			"key3": "val3",
			"key4": "val4",
		},
	}
}

// Tests the Set method by setting some variables and check if they are added to static
func TestReplacerSet(t *testing.T) {
	rep := fakeReplacer()

	for _, tc := range []struct {
		variable string
		value    string
	}{
		{
			variable: "test1",
			value:    "val1",
		},
		{
			variable: "asdf",
			value:    "123",
		},
		{
			variable: "äöü",
			value:    "öö_äü",
		},
		{
			variable: "with space",
			value:    "space value",
		},
		{
			variable: "1",
			value:    "test-123",
		},
		{
			variable: "mySuper_IP",
			value:    "1.2.3.4",
		},
		{
			variable: "testEmpty",
			value:    "",
		},
	} {
		rep.Set(tc.variable, tc.value)

		// test if key is added
		if val, ok := rep.static[tc.variable]; ok {
			if val != tc.value {
				t.Errorf("Expectd value '%s' for key '%s' got '%s'", tc.value, tc.variable, val)
			}
		} else {
			t.Errorf("Expectd existing key '%s' found nothing", tc.variable)
		}
	}

	// test if all keys are still there (by length)
	length := len(rep.static)
	if len(rep.static) != 7 {
		t.Errorf("Expectd length '%v' got '%v'", 7, length)
	}
}

func TestReplacerReplaceAll(t *testing.T) {
	rep := fakeReplacerFilled()

	for _, tc := range []struct {
		testInput string
		expected  string
	}{
		{
			// test vars without space
			testInput: "{test1}{asdf}{1}",
			expected:  "val1123test-123",
		},
		{
			// test vars with space
			testInput: "{test1} {asdf} {1} ",
			expected:  "val1 123 test-123 ",
		},
		{
			// test with empty val
			testInput: "{test1} {testEmpty} {asdf} {1} ",
			expected:  "val1 EMPTY 123 test-123 ",
		},
		{
			// test vars with not finished placeholders
			testInput: "{te{test1}{as{{df{1}",
			expected:  "{teval1{as{{dftest-123",
		},
		{
			// test with non existing vars
			testInput: "{test1} {nope} {1} ",
			expected:  "val1 {nope} test-123 ",
		},
	} {
		actual := rep.ReplaceAll(tc.testInput, "EMPTY")

		// test if all are replaced as expected
		if actual != tc.expected {
			t.Errorf("Expectd '%s' got '%s'", tc.expected, actual)
		}
	}
}

func TestReplacerDelete(t *testing.T) {
	rep := fakeReplacerFilledStatic()
	toDel := []string{
		"key2", "key4",
	}

	for _, key := range toDel {
		rep.Delete(key)

		// test if key is removed from static map
		if _, ok := rep.static[key]; ok {
			t.Errorf("Expectd '%s' to be removed. It is still in static map.", key)
		}
	}

	// check if static slice is smaller
	expected := len(fakeReplacerFilledStatic().static) - len(toDel)
	actual := len(rep.static)
	if len(rep.static) != expected {
		t.Errorf("Expectd length '%v' got lenth '%v'", expected, actual)
	}
}

func TestReplacerMap(t *testing.T) {
	rep := fakeReplacer()

	for i, tc := range []struct {
		key   string
		value string
	}{
		{
			key:   "f1",
			value: "v1",
		},
		{
			key:   "f2",
			value: "v2",
		},
	} {
		rep.Map(func(key string) (val string, ok bool) {
			if key == tc.key {
				return tc.value, true
			}
			return "NO", false
		})

		// test if function (which listens on specific key) is added bychecking length
		if len(rep.providers) == i+1 {
			val, _ := rep.providers[i](tc.key) // never fails, as we just checked the length
			// check if the last function is the one we just added
			if val != tc.value {
				t.Errorf("Expected value '%s' for key '%s' got '%s'", tc.value, tc.key, val)
			}
		} else {
			t.Errorf("Expected providers length '%v' got length '%v'", i+1, len(rep.providers))
		}
	}
}

func TestReplacerNew(t *testing.T) {
	var tc = NewReplacer()

	rep, ok := tc.(*replacer)
	if ok {
		if len(rep.providers) != 2 {
			t.Errorf("Expected providers length '%v' got length '%v'", 2, len(rep.providers))
		}
	} else {
		t.Errorf("Expected type of replacer %T got %T ", &replacer{}, tc)
	}
}
