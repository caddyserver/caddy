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

package rewrite

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func TestTo(t *testing.T) {
	fs := http.Dir("testdata")
	tests := []struct {
		url      string
		to       string
		expected string
	}{
		{"/", "/somefiles", "/somefiles"},
		{"/somefiles", "/somefiles /index.php{uri}", "/index.php/somefiles"},
		{"/somefiles", "/testfile /index.php{uri}", "/testfile"},
		{"/somefiles", "/testfile/ /index.php{uri}", "/index.php/somefiles"},
		{"/somefiles", "/somefiles /index.php{uri}", "/index.php/somefiles"},
		{"/?a=b", "/somefiles /index.php?{query}", "/index.php?a=b"},
		{"/?a=b", "/testfile /index.php?{query}", "/testfile?a=b"},
		{"/?a=b", "/testdir /index.php?{query}", "/index.php?a=b"},
		{"/?a=b", "/testdir/ /index.php?{query}", "/testdir/?a=b"},
		{"/test?url=http://", " /p/{path}?{query}", "/p/test?url=http://"},
		{"/test?url=http://", " /p/{rewrite_path}?{query}", "/p/test?url=http://"},
		{"/test/?url=http://", " /{uri}", "/test/?url=http://"},
	}

	uri := func(r *url.URL) string {
		uri := r.Path
		if r.RawQuery != "" {
			uri += "?" + r.RawQuery
		}
		return uri
	}
	for i, test := range tests {
		r, err := http.NewRequest("GET", test.url, nil)
		if err != nil {
			t.Error(err)
		}
		ctx := context.WithValue(r.Context(), httpserver.OriginalURLCtxKey, *r.URL)
		r = r.WithContext(ctx)
		To(fs, r, test.to, newReplacer(r))
		if uri(r.URL) != test.expected {
			t.Errorf("Test %v: expected %v found %v", i, test.expected, uri(r.URL))
		}
	}
}
