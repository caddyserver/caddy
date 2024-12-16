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
	"testing"
)

func TestBreadcrumbs(t *testing.T) {
	testdata := []struct {
		path     string
		expected []crumb
	}{
		{"", []crumb{}},
		{"/", []crumb{{Text: "/"}}},
		{"/foo/", []crumb{
			{Link: "../", Text: "/"},
			{Link: "", Text: "foo"},
		}},
		{"/foo/bar/", []crumb{
			{Link: "../../", Text: "/"},
			{Link: "../", Text: "foo"},
			{Link: "", Text: "bar"},
		}},
		{"/foo bar/", []crumb{
			{Link: "../", Text: "/"},
			{Link: "", Text: "foo bar"},
		}},
		{"/foo bar/baz/", []crumb{
			{Link: "../../", Text: "/"},
			{Link: "../", Text: "foo bar"},
			{Link: "", Text: "baz"},
		}},
		{"/100%25 test coverage/is a lie/", []crumb{
			{Link: "../../", Text: "/"},
			{Link: "../", Text: "100% test coverage"},
			{Link: "", Text: "is a lie"},
		}},
		{"/AC%2FDC/", []crumb{
			{Link: "../", Text: "/"},
			{Link: "", Text: "AC/DC"},
		}},
		{"/foo/%2e%2e%2f/bar", []crumb{
			{Link: "../../../", Text: "/"},
			{Link: "../../", Text: "foo"},
			{Link: "../", Text: "../"},
			{Link: "", Text: "bar"},
		}},
		{"/foo/../bar", []crumb{
			{Link: "../../../", Text: "/"},
			{Link: "../../", Text: "foo"},
			{Link: "../", Text: ".."},
			{Link: "", Text: "bar"},
		}},
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
	}

	for testNum, d := range testdata {
		l := browseTemplateContext{Path: d.path}
		actual := l.Breadcrumbs()
		if len(actual) != len(d.expected) {
			t.Errorf("Test %d: Got %d components but expected %d; got: %+v", testNum, len(actual), len(d.expected), actual)
			continue
		}
		for i, c := range actual {
			if c != d.expected[i] {
				t.Errorf("Test %d crumb %d: got %#v but expected %#v at index %d", testNum, i, c, d.expected[i], i)
			}
		}
	}
}
