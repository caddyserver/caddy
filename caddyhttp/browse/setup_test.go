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

package browse

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/caddyserver/caddy"
	"github.com/caddyserver/caddy/caddyhttp/httpserver"
)

func TestSetup(t *testing.T) {
	tempDirPath := os.TempDir()
	_, err := os.Stat(tempDirPath)
	if err != nil {
		t.Fatalf("BeforeTest: Failed to find an existing directory for testing! Error was: %v", err)
	}
	nonExistentDirPath := filepath.Join(tempDirPath, strconv.Itoa(int(time.Now().UnixNano())))

	tempTemplate, err := ioutil.TempFile(".", "tempTemplate")
	if err != nil {
		t.Fatalf("BeforeTest: Failed to create a temporary file in the working directory! Error was: %v", err)
	}
	defer os.Remove(tempTemplate.Name())

	tempTemplatePath := filepath.Join(".", tempTemplate.Name())

	for i, test := range []struct {
		input             string
		expectedPathScope []string
		shouldErr         bool
	}{
		// test case #0 tests handling of multiple pathscopes
		{"browse " + tempDirPath + "\n browse .", []string{tempDirPath, "."}, false},

		// test case #1 tests instantiation of Config with default values
		{"browse /", []string{"/"}, false},

		// test case #2 tests detection of custom template
		{"browse . " + tempTemplatePath, []string{"."}, false},

		// test case #3 tests detection of non-existent template
		{"browse . " + nonExistentDirPath, nil, true},

		// test case #4 tests detection of duplicate pathscopes
		{"browse " + tempDirPath + "\n browse " + tempDirPath, nil, true},
	} {

		c := caddy.NewTestController("http", test.input)
		err := setup(c)
		if err != nil && !test.shouldErr {
			t.Errorf("Test case #%d received an error of %v", i, err)
		}
		if test.expectedPathScope == nil {
			continue
		}
		mids := httpserver.GetConfig(c).Middleware()
		mid := mids[len(mids)-1]
		receivedConfigs := mid(nil).(Browse).Configs
		for j, config := range receivedConfigs {
			if config.PathScope != test.expectedPathScope[j] {
				t.Errorf("Test case #%d expected a pathscope of %v, but got %v", i, test.expectedPathScope, config.PathScope)
			}
		}
	}

	// test case #6 tests startup with missing root directory in combination with default browse settings
	controller := caddy.NewTestController("http", "browse")
	cfg := httpserver.GetConfig(controller)

	// Make sure non-existent root path doesn't return error
	cfg.Root = nonExistentDirPath
	err = setup(controller)

	if err != nil {
		t.Errorf("Test for non-existent browse path received an error, but shouldn't have: %v", err)
	}
}
