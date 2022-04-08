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

package fileserver

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestFileHidden(t *testing.T) {
	for i, tc := range []struct {
		inputShow []string
		inputHide []string
		inputPath string
		expect    bool
	}{
		{
			inputShow: nil,
			inputHide: nil,
			inputPath: "",
			expect:    false,
		},
		{
			inputShow: nil,
			inputHide: []string{".gitignore"},
			inputPath: "/.gitignore",
			expect:    true,
		},
		{
			inputShow: nil,
			inputHide: []string{".git"},
			inputPath: "/.gitignore",
			expect:    false,
		},
		{
			inputShow: nil,
			inputHide: []string{"/.git"},
			inputPath: "/.gitignore",
			expect:    false,
		},
		{
			inputShow: nil,
			inputHide: []string{".git"},
			inputPath: "/.git",
			expect:    true,
		},
		{
			inputShow: nil,
			inputHide: []string{".git"},
			inputPath: "/.git/foo",
			expect:    true,
		},
		{
			inputShow: nil,
			inputHide: []string{".git"},
			inputPath: "/foo/.git/bar",
			expect:    true,
		},
		{
			inputShow: nil,
			inputHide: []string{"/prefix"},
			inputPath: "/prefix/foo",
			expect:    true,
		},
		{
			inputShow: nil,
			inputHide: []string{"/foo/*/bar"},
			inputPath: "/foo/asdf/bar",
			expect:    true,
		},
		{
			inputShow: nil,
			inputHide: []string{"*.txt"},
			inputPath: "/foo/bar.txt",
			expect:    true,
		},
		{
			inputShow: nil,
			inputHide: []string{"/foo/bar/*.txt"},
			inputPath: "/foo/bar/baz.txt",
			expect:    true,
		},
		{
			inputShow: nil,
			inputHide: []string{"/foo/bar/*.txt"},
			inputPath: "/foo/bar.txt",
			expect:    false,
		},
		{
			inputShow: nil,
			inputHide: []string{"/foo/bar/*.txt"},
			inputPath: "/foo/bar/index.html",
			expect:    false,
		},
		{
			inputShow: nil,
			inputHide: []string{"/foo"},
			inputPath: "/foo",
			expect:    true,
		},
		{
			inputShow: nil,
			inputHide: []string{"/foo"},
			inputPath: "/foobar",
			expect:    false,
		},
		{
			inputShow: nil,
			inputHide: []string{"first", "second"},
			inputPath: "/second",
			expect:    true,
		},
		{
			inputShow: []string{"/foo"},
			inputHide: nil,
			inputPath: "/foobar",
			expect:    true,
		},
		{
			inputShow: []string{"/foo"},
			inputHide: nil,
			inputPath: "/foo/bar",
			expect:    false,
		},
		{
			inputShow: []string{"first", "second"},
			inputHide: nil,
			inputPath: "/third",
			expect:    true,
		},
		{
			inputShow: []string{"*.txt"},
			inputHide: nil,
			inputPath: "/foo/bar.txt",
			expect:    false,
		},
		{
			inputShow: []string{"*.txt"},
			inputHide: nil,
			inputPath: "/foo/bar.nope",
			expect:    true,
		},
		{
			inputShow: []string{"/foo"},
			inputHide: nil,
			inputPath: "/",
			expect:    false,
		},
		{
			inputShow: []string{"*.txt"},
			inputHide: []string{"/foo"},
			inputPath: "/foo/bar.txt",
			expect:    true,
		},
		{
			inputShow: []string{"*.txt"},
			inputHide: []string{"/foo"},
			inputPath: "/bar/baz.txt",
			expect:    false,
		},
	} {
		if runtime.GOOS == "windows" {
			if strings.HasPrefix(tc.inputPath, "/") {
				tc.inputPath, _ = filepath.Abs(tc.inputPath)
			}
			tc.inputPath = filepath.FromSlash(tc.inputPath)
			for i := range tc.inputShow {
				if strings.HasPrefix(tc.inputShow[i], "/") {
					tc.inputShow[i], _ = filepath.Abs(tc.inputShow[i])
				}
				tc.inputShow[i] = filepath.FromSlash(tc.inputShow[i])
			}
			for i := range tc.inputHide {
				if strings.HasPrefix(tc.inputHide[i], "/") {
					tc.inputHide[i], _ = filepath.Abs(tc.inputHide[i])
				}
				tc.inputHide[i] = filepath.FromSlash(tc.inputHide[i])
			}
		}

		actual := fileHidden(tc.inputPath, tc.inputShow, tc.inputHide)
		if actual != tc.expect {
			t.Errorf("Test %d: Is %s hidden by show(%v) hide(%v)? Got %t but expected %t",
				i, tc.inputPath, tc.inputShow, tc.inputHide, actual, tc.expect)
		}
	}
}
