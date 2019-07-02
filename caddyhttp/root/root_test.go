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

package root

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caddyserver/caddy"
	"github.com/caddyserver/caddy/caddyhttp/httpserver"
)

func TestRoot(t *testing.T) {
	// Predefined error substrings
	parseErrContent := "pars"
	unableToAccessErrContent := "Unable to access root path"

	existingDirPath, err := getTempDirPath()
	if err != nil {
		t.Fatalf("BeforeTest: Failed to find an existing directory for testing! Error was: %v", err)
	}

	nonexistentDir := filepath.Join(existingDirPath, "highly_unlikely_to_exist_dir")

	existingFile, err := ioutil.TempFile("", "root_test")
	if err != nil {
		t.Fatalf("BeforeTest: Failed to create temp file for testing! Error was: %v", err)
	}
	defer func() {
		existingFile.Close()
		os.Remove(existingFile.Name())
	}()

	inaccessiblePath := getInaccessiblePath(existingFile.Name())

	tests := []struct {
		input              string
		shouldErr          bool
		expectedRoot       string // expected root, set to the controller. Empty for negative cases.
		expectedErrContent string // substring from the expected error. Empty for positive cases.
	}{
		// positive
		{
			fmt.Sprintf(`root %s`, nonexistentDir), false, nonexistentDir, "",
		},
		{
			fmt.Sprintf(`root %s`, existingDirPath), false, existingDirPath, "",
		},
		// negative
		{
			`root `, true, "", parseErrContent,
		},
		{
			`root /a /b`, true, "", parseErrContent,
		},
		{
			fmt.Sprintf(`root %s`, inaccessiblePath), true, "", unableToAccessErrContent,
		},
		{
			fmt.Sprintf(`root {
				%s
			}`, existingDirPath), true, "", parseErrContent,
		},
	}

	for i, test := range tests {
		c := caddy.NewTestController("http", test.input)
		err := setupRoot(c)
		cfg := httpserver.GetConfig(c)

		if test.shouldErr && err == nil {
			t.Errorf("Test %d: Expected error but got nil for input '%s'", i, test.input)
		}

		if err != nil {
			if !test.shouldErr {
				t.Errorf("Test %d: Expected no error but found one for input %s. Error was: %v", i, test.input, err)
			}

			if !strings.Contains(err.Error(), test.expectedErrContent) {
				t.Errorf("Test %d: Expected error to contain '%v', found error: %v, input: %s", i, test.expectedErrContent, err, test.input)
			}
		}

		// check root only if we are in a positive test.
		if !test.shouldErr && test.expectedRoot != cfg.Root {
			t.Errorf("Root not correctly set for input %s. Expected: %s, actual: %s", test.input, test.expectedRoot, cfg.Root)
		}
	}
}

// getTempDirPath returns the path to the system temp directory. If it does not exists - an error is returned.
func getTempDirPath() (string, error) {
	tempDir := os.TempDir()
	_, err := os.Stat(tempDir)
	if err != nil {
		return "", err
	}
	return tempDir, nil
}

func getInaccessiblePath(file string) string {
	return filepath.Join("C:", "file\x00name") // null byte in filename is not allowed on Windows AND unix
}

func TestSymlinkRoot(t *testing.T) {
	origDir, err := ioutil.TempDir("", "root_test")
	if err != nil {
		t.Fatalf("BeforeTest: Failed to create temp dir for testing! Error was: %v", err)
	}
	defer func() {
		os.Remove(origDir)
	}()

	tempDir, err := getTempDirPath()
	if err != nil {
		t.Fatalf("BeforeTest: Failed to find an existing directory for testing! Error was: %v", err)
	}
	symlinkDir := filepath.Join(tempDir, "symlink")

	err = os.Symlink(origDir, symlinkDir)
	if err != nil {
		if strings.Contains(err.Error(), "A required privilege is not held by the client") {
			t.Skip("BeforeTest:  A required privilege is not held by the client and is required to create a symlink to run this test.")
		}
		t.Fatalf("BeforeTest: Cannot create symlink! Error was: %v", err)
	}
	defer func() {
		os.Remove(symlinkDir)
	}()

	input := fmt.Sprintf(`root %s`, symlinkDir)
	c := caddy.NewTestController("http", input)
	err = setupRoot(c)
	_ = httpserver.GetConfig(c)

	if err != nil {
		t.Errorf("Test Symlink Root: Expected no error but found one for input %s. Error was: %v", input, err)
	}
}
