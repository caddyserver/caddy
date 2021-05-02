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

package caddyhttp

import (
	"net/http"
	"testing"
)

func TestResponseMatcher(t *testing.T) {
	for i, tc := range []struct {
		require ResponseMatcher
		status  int
		hdr     http.Header // make sure these are canonical cased (std lib will do that in a real request)
		expect  bool
	}{
		{
			require: ResponseMatcher{},
			status:  200,
			expect:  true,
		},
		{
			require: ResponseMatcher{
				StatusCode: []int{200},
			},
			status: 200,
			expect: true,
		},
		{
			require: ResponseMatcher{
				StatusCode: []int{2},
			},
			status: 200,
			expect: true,
		},
		{
			require: ResponseMatcher{
				StatusCode: []int{201},
			},
			status: 200,
			expect: false,
		},
		{
			require: ResponseMatcher{
				StatusCode: []int{2},
			},
			status: 301,
			expect: false,
		},
		{
			require: ResponseMatcher{
				StatusCode: []int{3},
			},
			status: 301,
			expect: true,
		},
		{
			require: ResponseMatcher{
				StatusCode: []int{3},
			},
			status: 399,
			expect: true,
		},
		{
			require: ResponseMatcher{
				StatusCode: []int{3},
			},
			status: 400,
			expect: false,
		},
		{
			require: ResponseMatcher{
				StatusCode: []int{3, 4},
			},
			status: 400,
			expect: true,
		},
		{
			require: ResponseMatcher{
				StatusCode: []int{3, 401},
			},
			status: 401,
			expect: true,
		},
		{
			require: ResponseMatcher{
				Headers: http.Header{
					"Foo": []string{"bar"},
				},
			},
			hdr:    http.Header{"Foo": []string{"bar"}},
			expect: true,
		},
		{
			require: ResponseMatcher{
				Headers: http.Header{
					"Foo2": []string{"bar"},
				},
			},
			hdr:    http.Header{"Foo": []string{"bar"}},
			expect: false,
		},
		{
			require: ResponseMatcher{
				Headers: http.Header{
					"Foo": []string{"bar", "baz"},
				},
			},
			hdr:    http.Header{"Foo": []string{"baz"}},
			expect: true,
		},
		{
			require: ResponseMatcher{
				Headers: http.Header{
					"Foo":  []string{"bar"},
					"Foo2": []string{"baz"},
				},
			},
			hdr:    http.Header{"Foo": []string{"baz"}},
			expect: false,
		},
		{
			require: ResponseMatcher{
				Headers: http.Header{
					"Foo":  []string{"bar"},
					"Foo2": []string{"baz"},
				},
			},
			hdr:    http.Header{"Foo": []string{"bar"}, "Foo2": []string{"baz"}},
			expect: true,
		},
		{
			require: ResponseMatcher{
				Headers: http.Header{
					"Foo": []string{"foo*"},
				},
			},
			hdr:    http.Header{"Foo": []string{"foobar"}},
			expect: true,
		},
		{
			require: ResponseMatcher{
				Headers: http.Header{
					"Foo": []string{"foo*"},
				},
			},
			hdr:    http.Header{"Foo": []string{"foobar"}},
			expect: true,
		},
	} {
		actual := tc.require.Match(tc.status, tc.hdr)
		if actual != tc.expect {
			t.Errorf("Test %d %v: Expected %t, got %t for HTTP %d %v", i, tc.require, tc.expect, actual, tc.status, tc.hdr)
			continue
		}
	}
}
