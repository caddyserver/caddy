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

// Tests the Set method by setting some variables and replacing them afterwards.
func TestReplacerSet(t *testing.T) {
	replacer := NewReplacer()
	testInput := ""
	expected := ""

	// first add the variables
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
			value:    "098765",
		},
		{
			variable: "23456789",
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
		replacer.Set(tc.variable, tc.value)
		testInput += string(phOpen) + tc.variable + string(phClose)
		if tc.value == "" {
			expected += "EMPTY"
		} else {
			expected += tc.value
		}
	}

	testInput += string(phOpen) + "MyNotSetVariable" + string(phClose)
	expected += string(phOpen) + "MyNotSetVariable" + string(phClose)

	// then check if they are really replaced
	actual := replacer.ReplaceAll(testInput, "EMPTY")

	if actual != expected {
		t.Errorf("Expectd '%s', got '%s' for input '%s'", expected, actual, testInput)
	}
}

// Tests the Set method by setting some variables and replacing them afterwards.
// This test adds spaces between the placeholder
func TestReplacerSetWithSpaces(t *testing.T) {
	replacer := NewReplacer()
	testInput := ""
	expected := ""

	// first add the variables
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
			value:    "098765",
		},
		{
			variable: "23456789",
			value:    "öö_äü",
		},
	} {
		replacer.Set(tc.variable, tc.value)
		testInput += " " + string(phOpen) + tc.variable + string(phClose) + " "
		expected += " "
		if tc.value == "" {
			expected += "EMPTY"
		} else {
			expected += tc.value
		}
		expected += " "
	}

	testInput += " " + string(phOpen) + "MyNotSetVariable" + string(phClose) + " "
	expected += " " + string(phOpen) + "MyNotSetVariable" + string(phClose) + " "

	// then check if they are really replaced
	actual := replacer.ReplaceAll(testInput, "EMPTY")

	if actual != expected {
		t.Errorf("Expectd '%s', got '%s' for input '%s'", expected, actual, testInput)
	}
}

// Tests the Delete method by setting some variables, deleting some of them and replacing them afterwards.
// The deleted ones should not be replaced.
func TestReplacerDelete(t *testing.T) {
	replacer := NewReplacer()
	testInput := ""
	expected := ""
	toDeleteAfter := "toDeleteAfter"

	// first add the variables
	for _, tc := range []struct {
		variable string
		value    string
		delete   bool
	}{
		{
			variable: "test1",
			value:    "val1",
		},
		{
			variable: "asdf",
			value:    "123",
			delete:   true,
		},
		{
			variable: "äöü",
			value:    "098765",
		},
		{
			variable: "23456789",
			value:    "öö_äü",
			delete:   true,
		},
		{
			variable: "with space",
			value:    "space value",
			delete:   true,
		},
		{
			variable: "1",
			value:    "test-123",
		},
		{ // this one will be deleted after all were added and not instantly after adding
			variable: toDeleteAfter,
			value:    "test-123",
		},
		{
			variable: "mySuper_IP",
			value:    "1.2.3.4",
		},
		{
			variable: "testEmpty",
			value:    "",
			delete:   true,
		},
		{
			variable: "test2Empty",
			value:    "",
			delete:   true,
		},
	} {
		replacer.Set(tc.variable, tc.value)
		testInput += string(phOpen) + tc.variable + string(phClose)
		if tc.delete {
			expected += string(phOpen) + tc.variable + string(phClose)
			replacer.Delete(tc.variable)
		} else if tc.variable == toDeleteAfter {
			expected += string(phOpen) + tc.variable + string(phClose)
		} else if tc.value == "" {
			expected += "EMPTY"
		} else {
			expected += tc.value
		}
	}

	// Delete one key after all other ones to test if deleting it not directly after adding also workS
	replacer.Delete(toDeleteAfter)

	// then check if they are really replaced (except deleted ones)
	actual := replacer.ReplaceAll(testInput, "EMPTY")

	if actual != expected {
		t.Errorf("Expectd '%s', got '%s' for input '%s'", expected, actual, testInput)
	}
}

// Tests the Map method. Tests if the callback is actually called
func TestReplacerMapCalled(t *testing.T) {
	replacer := NewReplacer()

	// test if func is actually called for each occurence of key
	called := 0
	expect := 3
	input := "{test1} {test2}{test3}"

	replacer.Map(func(key string) (string, bool) {
		called++
		return "", false
	})
	replacer.ReplaceAll(input, "EMPTY")

	if called != expect {
		t.Errorf("Expected running replacer '%v' got '%v' runs for input '%s'", expect, called, input)
	}
}

// Tests the Map method.
// Tests if the placeholder is replaced.
// Tests if it replaces only if true is returned.
func TestReplacerMapReplace(t *testing.T) {
	replacer := NewReplacer()

	// test if it matches only if bool is false
	input := "{1} {0}{1}{2}-{3} {empty} "
	expect := "YAY {0}YAYHUHU-{3} EMPTY "

	replacer.Map(func(key string) (string, bool) {
		switch key {
		case "0":
			return "NOO", false
		case "1":
			return "YAY", true
		case "2":
			return "HUHU", true
		case "empty":
			return "", true
		default:
			return "_", false
		}
	})
	actual := replacer.ReplaceAll(input, "EMPTY")

	if actual != expect {
		t.Errorf("Expected '%s' got '%s' for input '%s'", expect, actual, input)
	}

	// test if an additional Replacer also works
	input = "{T2_1}{1} {0}{1}{T2_2} {2}-{3} {empty} "
	expect = "test21YAY {0}YAYtest22 HUHU-{3} EMPTY "

	replacer.Map(func(key string) (string, bool) {
		switch key {
		case "T2_1":
			return "test21", true
		case "T2_2":
			return "test22", true
		default:
			return "_", false
		}
	})

	actual = replacer.ReplaceAll(input, "EMPTY")

	if actual != expect {
		t.Errorf("Expected '%s' got '%s' for input '%s'", expect, actual, input)
	}
}
