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

package caddytls

import (
	"path/filepath"
	"testing"
)

// *********************************** NOTE ********************************
// Due to circular package dependencies with the storagetest sub package and
// the fact that we want to use that harness to test file storage, most of
// the tests for file storage are done in the storagetest package.

func TestPathBuilders(t *testing.T) {
	fs := FileStorage{Path: "test"}

	for i, testcase := range []struct {
		in, folder, certFile, keyFile, metaFile string
	}{
		{
			in:       "example.com",
			folder:   filepath.Join("test", "sites", "example.com"),
			certFile: filepath.Join("test", "sites", "example.com", "example.com.crt"),
			keyFile:  filepath.Join("test", "sites", "example.com", "example.com.key"),
			metaFile: filepath.Join("test", "sites", "example.com", "example.com.json"),
		},
		{
			in:       "*.example.com",
			folder:   filepath.Join("test", "sites", "wildcard_.example.com"),
			certFile: filepath.Join("test", "sites", "wildcard_.example.com", "wildcard_.example.com.crt"),
			keyFile:  filepath.Join("test", "sites", "wildcard_.example.com", "wildcard_.example.com.key"),
			metaFile: filepath.Join("test", "sites", "wildcard_.example.com", "wildcard_.example.com.json"),
		},
		{
			// prevent directory traversal! very important, esp. with on-demand TLS
			// see issue #2092
			in:       "a/../../../foo",
			folder:   filepath.Join("test", "sites", "afoo"),
			certFile: filepath.Join("test", "sites", "afoo", "afoo.crt"),
			keyFile:  filepath.Join("test", "sites", "afoo", "afoo.key"),
			metaFile: filepath.Join("test", "sites", "afoo", "afoo.json"),
		},
		{
			in:       "b\\..\\..\\..\\foo",
			folder:   filepath.Join("test", "sites", "bfoo"),
			certFile: filepath.Join("test", "sites", "bfoo", "bfoo.crt"),
			keyFile:  filepath.Join("test", "sites", "bfoo", "bfoo.key"),
			metaFile: filepath.Join("test", "sites", "bfoo", "bfoo.json"),
		},
		{
			in:       "c/foo",
			folder:   filepath.Join("test", "sites", "cfoo"),
			certFile: filepath.Join("test", "sites", "cfoo", "cfoo.crt"),
			keyFile:  filepath.Join("test", "sites", "cfoo", "cfoo.key"),
			metaFile: filepath.Join("test", "sites", "cfoo", "cfoo.json"),
		},
	} {
		if actual := fs.site(testcase.in); actual != testcase.folder {
			t.Errorf("Test %d: site folder: Expected '%s' but got '%s'", i, testcase.folder, actual)
		}
		if actual := fs.siteCertFile(testcase.in); actual != testcase.certFile {
			t.Errorf("Test %d: site cert file: Expected '%s' but got '%s'", i, testcase.certFile, actual)
		}
		if actual := fs.siteKeyFile(testcase.in); actual != testcase.keyFile {
			t.Errorf("Test %d: site key file: Expected '%s' but got '%s'", i, testcase.keyFile, actual)
		}
		if actual := fs.siteMetaFile(testcase.in); actual != testcase.metaFile {
			t.Errorf("Test %d: site meta file: Expected '%s' but got '%s'", i, testcase.metaFile, actual)
		}
	}
}
