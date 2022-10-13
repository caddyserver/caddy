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
	"context"
	"testing"
)

func TestBreadcrumbs(t *testing.T) {
	testdata := []struct {
		path     string
		expected []crumb
	}{
		{"", []crumb{}},
		{"/", []crumb{{Text: "/"}}},
		{"foo/bar/baz", []crumb{
			{Link: "../../", Text: "foo"},
			{Link: "../", Text: "bar"},
			{Link: "", Text: "baz"},
		}},
		{"/qux/quux/corge/", []crumb{
			{Link: "../../../", Text: "/"},
			{Link: "../../", Text: "qux"},
			{Link: "../", Text: "quux"},
			{Link: "", Text: "corge"},
		}},
		{"/مجلد/", []crumb{
			{Link: "../", Text: "/"},
			{Link: "", Text: "مجلد"},
		}},
		{"/مجلد-1/مجلد-2", []crumb{
			{Link: "../../", Text: "/"},
			{Link: "../", Text: "مجلد-1"},
			{Link: "", Text: "مجلد-2"},
		}},
		{"/مجلد%2F1", []crumb{
			{Link: "../", Text: "/"},
			{Link: "", Text: "مجلد/1"},
		}},
		{"with %2f encoded %2F/slashes/not % 2F encoded", []crumb{
			{Link: "../../", Text: "with / encoded /"},
			{Link: "../", Text: "slashes"},
			{Link: "", Text: "not % 2F encoded"},
		}},
		{"folder/with % sign/sub", []crumb{
			{Link: "../../", Text: "folder"},
			{Link: "../", Text: "with % sign"},
			{Link: "", Text: "sub"},
		}},
	}

	for _, d := range testdata {
		l := browseTemplateContext{Path: d.path}
		actual := l.Breadcrumbs()
		if len(actual) != len(d.expected) {
			t.Errorf("wrong size output, got %d elements but expected %d", len(actual), len(d.expected))
			continue
		}
		for i, c := range actual {
			if c != d.expected[i] {
				t.Errorf("got %#v but expected %#v at index %d", c, d.expected[i], i)
			}
		}
	}
}

func TestFileServer_directoryListing(t *testing.T) {
	tests := []struct {
		name         string
		urlPath      string
		expectedName string
	}{
		{
			name:         "dir with percent sign",
			urlPath:      "/path/with%percent",
			expectedName: "with%percent",
		},
		{
			name:         "percent-encoded slash",
			urlPath:      "/path/with%2Fslash",
			expectedName: "with/slash",
		},
		{
			name:         "other percent-encoded chars",
			urlPath:      "/path/with%20space",
			expectedName: "with%20space",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsrv := FileServer{}
			bCtx := fsrv.directoryListing(
				context.Background(),
				nil,
				false,
				"/path/to/root",
				tt.urlPath,
				nil,
			)
			actual := bCtx.Name
			if actual != tt.expectedName {
				t.Errorf("got %+v but expected %+v", actual, tt.expectedName)
			}
		})
	}
}
