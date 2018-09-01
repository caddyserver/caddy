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

package httpserver

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/mholt/caddy"
)

func TestConditions(t *testing.T) {
	tests := []struct {
		condition string
		isTrue    bool
		shouldErr bool
	}{
		{"a is b", false, false},
		{"a is a", true, false},
		{"a not b", true, false},
		{"a not a", false, false},
		{"a has a", true, false},
		{"a has b", false, false},
		{"ba has b", true, false},
		{"bab has b", true, false},
		{"bab has bb", false, false},
		{"a not_has a", false, false},
		{"a not_has b", true, false},
		{"ba not_has b", false, false},
		{"bab not_has b", false, false},
		{"bab not_has bb", true, false},
		{"bab starts_with bb", false, false},
		{"bab starts_with ba", true, false},
		{"bab starts_with bab", true, false},
		{"bab not_starts_with bb", true, false},
		{"bab not_starts_with ba", false, false},
		{"bab not_starts_with bab", false, false},
		{"bab ends_with bb", false, false},
		{"bab ends_with bab", true, false},
		{"bab ends_with ab", true, false},
		{"bab not_ends_with bb", true, false},
		{"bab not_ends_with ab", false, false},
		{"bab not_ends_with bab", false, false},
		{"a match *", false, true},
		{"a match a", true, false},
		{"a match .*", true, false},
		{"a match a.*", true, false},
		{"a match b.*", false, false},
		{"ba match b.*", true, false},
		{"ba match b[a-z]", true, false},
		{"b0 match b[a-z]", false, false},
		{"b0a match b[a-z]", false, false},
		{"b0a match b[a-z]+", false, false},
		{"b0a match b[a-z0-9]+", true, false},
		{"bac match b[a-z]{2}", true, false},
		{"a not_match *", false, true},
		{"a not_match a", false, false},
		{"a not_match .*", false, false},
		{"a not_match a.*", false, false},
		{"a not_match b.*", true, false},
		{"ba not_match b.*", false, false},
		{"ba not_match b[a-z]", false, false},
		{"b0 not_match b[a-z]", true, false},
		{"b0a not_match b[a-z]", true, false},
		{"b0a not_match b[a-z]+", true, false},
		{"b0a not_match b[a-z0-9]+", false, false},
		{"bac not_match b[a-z]{2}", false, false},
	}

	for i, test := range tests {
		str := strings.Fields(test.condition)
		ifCond, err := newIfCond(str[0], str[1], str[2])
		if err != nil {
			if !test.shouldErr {
				t.Error(err)
			}
			continue
		}
		isTrue := ifCond.True(nil)
		if isTrue != test.isTrue {
			t.Errorf("Test %d: '%s' expected %v found %v", i, test.condition, test.isTrue, isTrue)
		}
	}

	invalidOperators := []string{"ss", "and", "if"}
	for _, op := range invalidOperators {
		_, err := newIfCond("a", op, "b")
		if err == nil {
			t.Errorf("Invalid operator %v used, expected error.", op)
		}
	}

	replaceTests := []struct {
		url       string
		condition string
		isTrue    bool
	}{
		{"/home", "{uri} match /home", true},
		{"/hom", "{uri} match /home", false},
		{"/hom", "{uri} starts_with /home", false},
		{"/hom", "{uri} starts_with /h", true},
		{"/home/.hiddenfile", `{uri} match \/\.(.*)`, true},
		{"/home/.hiddendir/afile", `{uri} match \/\.(.*)`, true},
	}

	for i, test := range replaceTests {
		r, err := http.NewRequest("GET", test.url, nil)
		if err != nil {
			t.Errorf("Test %d: failed to create request: %v", i, err)
			continue
		}
		ctx := context.WithValue(r.Context(), OriginalURLCtxKey, *r.URL)
		r = r.WithContext(ctx)
		str := strings.Fields(test.condition)
		ifCond, err := newIfCond(str[0], str[1], str[2])
		if err != nil {
			t.Errorf("Test %d: failed to create 'if' condition %v", i, err)
			continue
		}
		isTrue := ifCond.True(r)
		if isTrue != test.isTrue {
			t.Errorf("Test %v: expected %v found %v", i, test.isTrue, isTrue)
			continue
		}
	}
}

func TestIfMatcher(t *testing.T) {
	tests := []struct {
		conditions []string
		isOr       bool
		isTrue     bool
	}{
		{
			[]string{
				"a is a",
				"b is b",
				"c is c",
			},
			false,
			true,
		},
		{
			[]string{
				"a is b",
				"b is c",
				"c is c",
			},
			true,
			true,
		},
		{
			[]string{
				"a is a",
				"b is a",
				"c is c",
			},
			false,
			false,
		},
		{
			[]string{
				"a is b",
				"b is c",
				"c is a",
			},
			true,
			false,
		},
		{
			[]string{},
			false,
			true,
		},
		{
			[]string{},
			true,
			false,
		},
	}

	for i, test := range tests {
		matcher := IfMatcher{isOr: test.isOr}
		for _, condition := range test.conditions {
			str := strings.Fields(condition)
			ifCond, err := newIfCond(str[0], str[1], str[2])
			if err != nil {
				t.Error(err)
			}
			matcher.ifs = append(matcher.ifs, ifCond)
		}
		isTrue := matcher.Match(nil)
		if isTrue != test.isTrue {
			t.Errorf("Test %d: expected %v found %v", i, test.isTrue, isTrue)
		}
	}
}

func TestSetupIfMatcher(t *testing.T) {
	rex_b, _ := regexp.Compile("b")
	tests := []struct {
		input     string
		shouldErr bool
		expected  IfMatcher
	}{
		{`test {
			if	a match b
		 }`, false, IfMatcher{
			ifs: []ifCond{
				{a: "a", op: "match", b: "b", neg: false, rex: rex_b},
			},
		}},
		{`test {
			if a match b
			if_op or
		 }`, false, IfMatcher{
			ifs: []ifCond{
				{a: "a", op: "match", b: "b", neg: false, rex: rex_b},
			},
			isOr: true,
		}},
		{`test {
			if	a match
		 }`, true, IfMatcher{},
		},
		{`test {
			if	a isn't b
		 }`, true, IfMatcher{},
		},
		{`test {
			if a match b c
		 }`, true, IfMatcher{},
		},
		{`test {
			if goal has go
			if cook not_has go
		 }`, false, IfMatcher{
			ifs: []ifCond{
				{a: "goal", op: "has", b: "go", neg: false},
				{a: "cook", op: "has", b: "go", neg: true},
			},
		}},
		{`test {
			if goal has go
			if cook not_has go
			if_op and
		 }`, false, IfMatcher{
			ifs: []ifCond{
				{a: "goal", op: "has", b: "go", neg: false},
				{a: "cook", op: "has", b: "go", neg: true},
			},
		}},
		{`test {
			if goal has go
			if cook not_has go
			if_op not
		 }`, true, IfMatcher{},
		},
	}

	for i, test := range tests {
		c := caddy.NewTestController("http", test.input)
		c.Next()

		matcher, err := SetupIfMatcher(c)
		if err == nil && test.shouldErr {
			t.Errorf("Test %d didn't error, but it should have", i)
		} else if err != nil && !test.shouldErr {
			t.Errorf("Test %d errored, but it shouldn't have; got '%v'", i, err)
		} else if err != nil && test.shouldErr {
			continue
		}

		test_if, ok := matcher.(IfMatcher)
		if !ok {
			t.Error("RequestMatcher should be of type IfMatcher")
		}

		if err != nil {
			t.Errorf("Expected no error, but got: %v", err)
		}

		if len(test_if.ifs) != len(test.expected.ifs) {
			t.Errorf("Test %d: Expected %d ifConditions, found %v", i,
				len(test.expected.ifs), len(test_if.ifs))
		}

		for j, if_c := range test_if.ifs {
			expected_c := test.expected.ifs[j]

			if if_c.a != expected_c.a {
				t.Errorf("Test %d, ifCond %d: Expected A=%s, got %s",
					i, j, if_c.a, expected_c.a)
			}

			if if_c.op != expected_c.op {
				t.Errorf("Test %d, ifCond %d: Expected Op=%s, got %s",
					i, j, if_c.op, expected_c.op)
			}

			if if_c.b != expected_c.b {
				t.Errorf("Test %d, ifCond %d: Expected B=%s, got %s",
					i, j, if_c.b, expected_c.b)
			}

			if if_c.neg != expected_c.neg {
				t.Errorf("Test %d, ifCond %d: Expected Neg=%v, got %v",
					i, j, if_c.neg, expected_c.neg)
			}

			if expected_c.rex != nil && if_c.rex == nil {
				t.Errorf("Test %d, ifCond %d: Expected Rex=%v, got <nil>",
					i, j, expected_c.rex)
			}

			if expected_c.rex == nil && if_c.rex != nil {
				t.Errorf("Test %d, ifCond %d: Expected Rex=<nil>, got %v",
					i, j, if_c.rex)
			}

			if expected_c.rex != nil && if_c.rex != nil {
				if if_c.rex.String() != expected_c.rex.String() {
					t.Errorf("Test %d, ifCond %d: Expected Rex=%v, got %v",
						i, j, if_c.rex, expected_c.rex)
				}
			}
		}
	}
}

func TestIfMatcherKeyword(t *testing.T) {
	tests := []struct {
		keyword  string
		expected bool
	}{
		{"if", true},
		{"ifs", false},
		{"tls", false},
		{"http", false},
		{"if_op", true},
		{"if_type", false},
		{"if_cond", false},
	}

	for i, test := range tests {
		c := caddy.NewTestController("http", test.keyword)
		c.Next()
		valid := IfMatcherKeyword(c)
		if valid != test.expected {
			t.Errorf("Test %d: expected %v found %v", i, test.expected, valid)
		}
	}
}
