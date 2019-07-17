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
