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

package caddymain

import (
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestSetCPU(t *testing.T) {
	currentCPU := runtime.GOMAXPROCS(-1)
	maxCPU := runtime.NumCPU()
	halfCPU := int(0.5 * float32(maxCPU))
	if halfCPU < 1 {
		halfCPU = 1
	}
	for i, test := range []struct {
		input     string
		output    int
		shouldErr bool
	}{
		{"1", 1, false},
		{"-1", currentCPU, true},
		{"0", currentCPU, true},
		{"100%", maxCPU, false},
		{"50%", halfCPU, false},
		{"110%", currentCPU, true},
		{"-10%", currentCPU, true},
		{"invalid input", currentCPU, true},
		{"invalid input%", currentCPU, true},
		{"9999", maxCPU, false}, // over available CPU
		{"1%", 1, false},        // under a single CPU; assume maxCPU < 100
	} {
		err := setCPU(test.input)
		if test.shouldErr && err == nil {
			t.Errorf("Test %d: Expected error, but there wasn't any", i)
		}
		if !test.shouldErr && err != nil {
			t.Errorf("Test %d: Expected no error, but there was one: %v", i, err)
		}
		if actual, expected := runtime.GOMAXPROCS(-1), test.output; actual != expected {
			t.Errorf("Test %d: GOMAXPROCS was %d but expected %d", i, actual, expected)
		}
		// teardown
		runtime.GOMAXPROCS(currentCPU)
	}
}

func TestSplitTrim(t *testing.T) {
	for i, test := range []struct {
		input  string
		output []string
		sep    string
	}{
		{"os,arch,cpu,caddy_version", []string{"os", "arch", "cpu", "caddy_version"}, ","},
		{"os,arch,cpu,caddy_version,", []string{"os", "arch", "cpu", "caddy_version"}, ","},
		{"os,,, arch, cpu, caddy_version,", []string{"os", "arch", "cpu", "caddy_version"}, ","},
		{", , os, arch, cpu , caddy_version,, ,", []string{"os", "arch", "cpu", "caddy_version"}, ","},
		{"os, ,, arch, cpu , caddy_version,, ,", []string{"os", "arch", "cpu", "caddy_version"}, ","},
	} {
		got := splitTrim(test.input, test.sep)
		if len(got) != len(test.output) {
			t.Errorf("Test %d: spliteTrim() = %v, want %v", i, got, test.output)
			continue
		}
		for j, item := range test.output {
			if item != got[j] {
				t.Errorf("Test %d: spliteTrim() = %v, want %v", i, got, test.output)
				break
			}
		}
	}
}

func TestParseEnvFile(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    map[string]string
		wantErr bool
	}{
		{"parsing KEY=VALUE", "PORT=4096", map[string]string{"PORT": "4096"}, false},
		{"empty KEY", "=4096", nil, true},
		{"one value", "test", nil, true},
		{"comments skipped", "#TEST=1\nPORT=8888", map[string]string{"PORT": "8888"}, false},
		{"empty line", "\nPORT=7777", map[string]string{"PORT": "7777"}, false},
		{"comments with space skipped", "  #TEST=1", map[string]string{}, false},
		{"KEY with space", "PORT =8888", nil, true},
		{"only spaces", "   ", map[string]string{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := strings.NewReader(tt.input)
			got, err := ParseEnvFile(reader)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseEnvFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseEnvFile() = %v, want %v", got, tt.want)
			}
		})
	}
}
