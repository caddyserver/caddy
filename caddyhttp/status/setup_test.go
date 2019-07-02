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

package status

import (
	"testing"

	"github.com/caddyserver/caddy"
	"github.com/caddyserver/caddy/caddyhttp/httpserver"
)

func TestSetup(t *testing.T) {
	c := caddy.NewTestController("http", `status 404 /foo`)
	err := setup(c)
	if err != nil {
		t.Errorf("Expected no errors, but got: %v", err)
	}

	mids := httpserver.GetConfig(c).Middleware()
	if len(mids) == 0 {
		t.Fatal("Expected middleware, had 0 instead")
	}

	handler := mids[0](httpserver.EmptyNext)
	myHandler, ok := handler.(Status)
	if !ok {
		t.Fatalf("Expected handler to be type Status, got: %#v",
			handler)
	}

	if !httpserver.SameNext(myHandler.Next, httpserver.EmptyNext) {
		t.Error("'Next' field of handler was not set properly")
	}

	if len(myHandler.Rules) != 1 {
		t.Errorf("Expected handler to have %d rule, has %d instead", 1, len(myHandler.Rules))
	}
}

func TestStatusParse(t *testing.T) {
	tests := []struct {
		input     string
		shouldErr bool
		expected  []*Rule
	}{
		{`status`, true, []*Rule{}},
		{`status /foo`, true, []*Rule{}},
		{`status bar /foo`, true, []*Rule{}},
		{`status 404 /foo bar`, true, []*Rule{}},
		{`status 404 /foo`, false, []*Rule{
			{Base: "/foo", StatusCode: 404},
		},
		},
		{`status {
		 }`,
			true,
			[]*Rule{},
		},
		{`status 404 {
		 }`,
			true,
			[]*Rule{},
		},
		{`status 404 {
			/foo
			/foo
		 }`,
			true,
			[]*Rule{},
		},
		{`status 404 {
			404 /foo
		 }`,
			true,
			[]*Rule{},
		},
		{`status 404 {
			/foo
			/bar
		 }`,
			false,
			[]*Rule{
				{Base: "/foo", StatusCode: 404},
				{Base: "/bar", StatusCode: 404},
			},
		},
	}

	for i, test := range tests {
		actual, err := statusParse(caddy.NewTestController("http",
			test.input))

		if err == nil && test.shouldErr {
			t.Errorf("Test %d didn't error, but it should have", i)
		} else if err != nil && !test.shouldErr {
			t.Errorf("Test %d errored, but it shouldn't have; got '%v'",
				i, err)
		} else if err != nil && test.shouldErr {
			continue
		}

		if len(actual) != len(test.expected) {
			t.Fatalf("Test %d expected %d rules, but got %d",
				i, len(test.expected), len(actual))
		}

		findRule := func(basePath string) (bool, *Rule) {
			for _, cfg := range actual {
				actualRule := cfg.(*Rule)

				if actualRule.Base == basePath {
					return true, actualRule
				}
			}

			return false, nil
		}

		for _, expectedRule := range test.expected {
			found, actualRule := findRule(expectedRule.Base)

			if !found {
				t.Errorf("Test %d: Missing rule for path '%s'",
					i, expectedRule.Base)
			}

			if actualRule.StatusCode != expectedRule.StatusCode {
				t.Errorf("Test %d: Expected status code %d for path '%s'. Got %d",
					i, expectedRule.StatusCode, expectedRule.Base, actualRule.StatusCode)
			}
		}
	}
}
