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

package limits

import (
	"reflect"
	"testing"

	"github.com/caddyserver/caddy"
	"github.com/caddyserver/caddy/caddyhttp/httpserver"
)

const (
	KB = 1024
	MB = 1024 * 1024
	GB = 1024 * 1024 * 1024
)

func TestParseLimits(t *testing.T) {
	for name, c := range map[string]struct {
		input     string
		shouldErr bool
		expect    httpserver.Limits
	}{
		"catchAll": {
			input: `limits 2kb`,
			expect: httpserver.Limits{
				MaxRequestHeaderSize: 2 * KB,
				MaxRequestBodySizes:  []httpserver.PathLimit{{Path: "/", Limit: 2 * KB}},
			},
		},
		"onlyHeader": {
			input: `limits {
				header 2kb
			}`,
			expect: httpserver.Limits{
				MaxRequestHeaderSize: 2 * KB,
			},
		},
		"onlyBody": {
			input: `limits {
				body 2kb
			}`,
			expect: httpserver.Limits{
				MaxRequestBodySizes: []httpserver.PathLimit{{Path: "/", Limit: 2 * KB}},
			},
		},
		"onlyBodyWithPath": {
			input: `limits {
				body /test 2kb
			}`,
			expect: httpserver.Limits{
				MaxRequestBodySizes: []httpserver.PathLimit{{Path: "/test", Limit: 2 * KB}},
			},
		},
		"mixture": {
			input: `limits {
				header 1kb
				body 2kb
				body /bar 3kb
			}`,
			expect: httpserver.Limits{
				MaxRequestHeaderSize: 1 * KB,
				MaxRequestBodySizes: []httpserver.PathLimit{
					{Path: "/bar", Limit: 3 * KB},
					{Path: "/", Limit: 2 * KB},
				},
			},
		},
		"invalidFormat": {
			input:     `limits a b`,
			shouldErr: true,
		},
		"invalidHeaderFormat": {
			input: `limits {
				header / 100
			}`,
			shouldErr: true,
		},
		"invalidBodyFormat": {
			input: `limits {
				body / 100 200
			}`,
			shouldErr: true,
		},
		"invalidKind": {
			input: `limits {
				head 100
			}`,
			shouldErr: true,
		},
		"invalidLimitSize": {
			input:     `limits 10bk`,
			shouldErr: true,
		},
	} {
		c := c
		t.Run(name, func(t *testing.T) {
			controller := caddy.NewTestController("", c.input)
			_, err := parseLimits(controller)
			if c.shouldErr && err == nil {
				t.Error("failed to get expected error")
			}
			if !c.shouldErr && err != nil {
				t.Errorf("got unexpected error: %v", err)
			}
			if got := httpserver.GetConfig(controller).Limits; !reflect.DeepEqual(got, c.expect) {
				t.Errorf("expect %#v, but got %#v", c.expect, got)
			}
		})
	}
}

func TestParseArguments(t *testing.T) {
	cases := []struct {
		arguments []pathLimitUnparsed
		expected  []httpserver.PathLimit
		hasError  bool
	}{
		// Parse errors
		{arguments: []pathLimitUnparsed{{"/", "123.5"}}, expected: []httpserver.PathLimit{}, hasError: true},
		{arguments: []pathLimitUnparsed{{"/", "200LB"}}, expected: []httpserver.PathLimit{}, hasError: true},
		{arguments: []pathLimitUnparsed{{"/", "path:999MB"}}, expected: []httpserver.PathLimit{}, hasError: true},
		{arguments: []pathLimitUnparsed{{"/", "1_234_567"}}, expected: []httpserver.PathLimit{}, hasError: true},
		{arguments: []pathLimitUnparsed{{"/", "0MB"}}, expected: []httpserver.PathLimit{}, hasError: true},

		// Valid results
		{arguments: []pathLimitUnparsed{}, expected: []httpserver.PathLimit{}, hasError: false},
		{
			arguments: []pathLimitUnparsed{{"/", "100"}},
			expected:  []httpserver.PathLimit{{Path: "/", Limit: 100}},
			hasError:  false,
		},
		{
			arguments: []pathLimitUnparsed{{"/", "100KB"}},
			expected:  []httpserver.PathLimit{{Path: "/", Limit: 100 * KB}},
			hasError:  false,
		},
		{
			arguments: []pathLimitUnparsed{{"/", "100MB"}},
			expected:  []httpserver.PathLimit{{Path: "/", Limit: 100 * MB}},
			hasError:  false,
		},
		{
			arguments: []pathLimitUnparsed{{"/", "100GB"}},
			expected:  []httpserver.PathLimit{{Path: "/", Limit: 100 * GB}},
			hasError:  false,
		},
		{
			arguments: []pathLimitUnparsed{{"index", "100"}},
			expected:  []httpserver.PathLimit{{Path: "/index", Limit: 100}},
			hasError:  false,
		},
		{
			arguments: []pathLimitUnparsed{{"/home", "100MB"}, {"/upload/images", "500GB"}},
			expected: []httpserver.PathLimit{
				{Path: "/home", Limit: 100 * MB},
				{Path: "/upload/images", Limit: 500 * GB},
			},
			hasError: false},
		{
			arguments: []pathLimitUnparsed{{"/", "999"}, {"/home", "12345MB"}},
			expected: []httpserver.PathLimit{
				{Path: "/", Limit: 999},
				{Path: "/home", Limit: 12345 * MB},
			},
			hasError: false,
		},

		// Duplicates
		{
			arguments: []pathLimitUnparsed{{"/home", "999"}, {"/home", "12345MB"}},
			expected: []httpserver.PathLimit{
				{Path: "/home", Limit: 12345 * MB},
			},
			hasError: false,
		},
	}

	for caseNum, c := range cases {
		output, err := parseArguments(c.arguments)
		if c.hasError && (err == nil) {
			t.Errorf("Expecting error for case %v but none encountered", caseNum)
		}
		if !c.hasError && (err != nil) {
			t.Errorf("Expecting no error for case %v but encountered %v", caseNum, err)
		}

		if !reflect.DeepEqual(c.expected, output) {
			t.Errorf("Case %v is expecting: %v, actual %v", caseNum, c.expected, output)
		}
	}
}

func TestSortPathLimits(t *testing.T) {
	cases := []struct {
		arguments []httpserver.PathLimit
		expected  []httpserver.PathLimit
	}{
		// Parse errors
		{arguments: []httpserver.PathLimit{}, expected: []httpserver.PathLimit{}},
		{
			arguments: []httpserver.PathLimit{{Path: "/index", Limit: 100}},
			expected:  []httpserver.PathLimit{{Path: "/index", Limit: 100}},
		},
		{
			arguments: []httpserver.PathLimit{
				{Path: "/static", Limit: 1},
				{Path: "/static/images", Limit: 100},
				{Path: "/index", Limit: 200},
			},
			expected: []httpserver.PathLimit{
				{Path: "/static/images", Limit: 100},
				{Path: "/static", Limit: 1},
				{Path: "/index", Limit: 200}},
		},
	}

	for caseNum, c := range cases {
		output := append([]httpserver.PathLimit{}, c.arguments...)
		SortPathLimits(output)
		if !reflect.DeepEqual(c.expected, output) {
			t.Errorf("Case %v is expecting: %v, actual %v", caseNum, c.expected, output)
		}
	}
}
