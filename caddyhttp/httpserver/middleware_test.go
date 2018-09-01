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

package httpserver

import (
	"os"
	"testing"
)

func TestPathCaseSensitivity(t *testing.T) {
	tests := []struct {
		basePath      string
		path          string
		caseSensitive bool
		expected      bool
	}{
		{"/", "/file", true, true},
		{"/a", "/file", true, false},
		{"/f", "/file", true, true},
		{"/f", "/File", true, false},
		{"/f", "/File", false, true},
		{"/file", "/file", true, true},
		{"/file", "/file", false, true},
		{"/files", "/file", false, false},
		{"/files", "/file", true, false},
		{"/folder", "/folder/file.txt", true, true},
		{"/folders", "/folder/file.txt", true, false},
		{"/folder", "/Folder/file.txt", false, true},
		{"/folders", "/Folder/file.txt", false, false},
	}

	for i, test := range tests {
		CaseSensitivePath = test.caseSensitive
		valid := Path(test.path).Matches(test.basePath)
		if test.expected != valid {
			t.Errorf("Test %d: Expected %v, found %v", i, test.expected, valid)
		}
	}
}

func TestPathCaseSensitiveEnv(t *testing.T) {
	tests := []struct {
		envValue string
		expected bool
	}{
		{"1", true},
		{"0", false},
		{"false", false},
		{"true", true},
		{"", false},
	}

	for i, test := range tests {
		os.Setenv(caseSensitivePathEnv, test.envValue)
		initCaseSettings()
		if test.expected != CaseSensitivePath {
			t.Errorf("Test %d: Expected %v, found %v", i, test.expected, CaseSensitivePath)
		}
	}
}
