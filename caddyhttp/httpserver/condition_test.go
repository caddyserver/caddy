package httpserver

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/mholt/caddy"
)

func TestConditions(t *testing.T) {
	tests := []struct {
		condition string
		isTrue    bool
	}{
		{"a is b", false},
		{"a is a", true},
		{"a not b", true},
		{"a not a", false},
		{"a has a", true},
		{"a has b", false},
		{"ba has b", true},
		{"bab has b", true},
		{"bab has bb", false},
		{"a not_has a", false},
		{"a not_has b", true},
		{"ba not_has b", false},
		{"bab not_has b", false},
		{"bab not_has bb", true},
		{"bab starts_with bb", false},
		{"bab starts_with ba", true},
		{"bab starts_with bab", true},
		{"bab ends_with bb", false},
		{"bab ends_with bab", true},
		{"bab ends_with ab", true},
		{"a match *", false},
		{"a match a", true},
		{"a match .*", true},
		{"a match a.*", true},
		{"a match b.*", false},
		{"ba match b.*", true},
		{"ba match b[a-z]", true},
		{"b0 match b[a-z]", false},
		{"b0a match b[a-z]", false},
		{"b0a match b[a-z]+", false},
		{"b0a match b[a-z0-9]+", true},
		{"a not_match *", true},
		{"a not_match a", false},
		{"a not_match .*", false},
		{"a not_match a.*", false},
		{"a not_match b.*", true},
		{"ba not_match b.*", false},
		{"ba not_match b[a-z]", false},
		{"b0 not_match b[a-z]", true},
		{"b0a not_match b[a-z]", true},
		{"b0a not_match b[a-z]+", true},
		{"b0a not_match b[a-z0-9]+", false},
	}

	for i, test := range tests {
		str := strings.Fields(test.condition)
		ifCond, err := newIfCond(str[0], str[1], str[2])
		if err != nil {
			t.Error(err)
		}
		isTrue := ifCond.True(nil)
		if isTrue != test.isTrue {
			t.Errorf("Test %d: expected %v found %v", i, test.isTrue, isTrue)
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
			t.Error(err)
		}
		str := strings.Fields(test.condition)
		ifCond, err := newIfCond(str[0], str[1], str[2])
		if err != nil {
			t.Error(err)
		}
		isTrue := ifCond.True(r)
		if isTrue != test.isTrue {
			t.Errorf("Test %v: expected %v found %v", i, test.isTrue, isTrue)
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
	tests := []struct {
		input     string
		shouldErr bool
		expected  IfMatcher
	}{
		{`test {
			if	a match b
		 }`, false, IfMatcher{
			ifs: []ifCond{
				{a: "a", op: "match", b: "b"},
			},
		}},
		{`test {
			if a match b
			if_op or
		 }`, false, IfMatcher{
			ifs: []ifCond{
				{a: "a", op: "match", b: "b"},
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
				{a: "goal", op: "has", b: "go"},
				{a: "cook", op: "not_has", b: "go"},
			},
		}},
		{`test {
			if goal has go
			if cook not_has go 
			if_op and
		 }`, false, IfMatcher{
			ifs: []ifCond{
				{a: "goal", op: "has", b: "go"},
				{a: "cook", op: "not_has", b: "go"},
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
		if _, ok := matcher.(IfMatcher); !ok {
			t.Error("RequestMatcher should be of type IfMatcher")
		}
		if err != nil {
			t.Errorf("Expected no error, but got: %v", err)
		}
		if fmt.Sprint(matcher) != fmt.Sprint(test.expected) {
			t.Errorf("Test %v: Expected %v, found %v", i,
				fmt.Sprint(test.expected), fmt.Sprint(matcher))
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
