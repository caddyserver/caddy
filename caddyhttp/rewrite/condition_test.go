package rewrite

import (
	"net/http"
	"strings"
	"testing"
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
		ifCond, err := NewIf(str[0], str[1], str[2])
		if err != nil {
			t.Error(err)
		}
		isTrue := ifCond.True(nil)
		if isTrue != test.isTrue {
			t.Errorf("Test %v: expected %v found %v", i, test.isTrue, isTrue)
		}
	}

	invalidOperators := []string{"ss", "and", "if"}
	for _, op := range invalidOperators {
		_, err := NewIf("a", op, "b")
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
		ifCond, err := NewIf(str[0], str[1], str[2])
		if err != nil {
			t.Error(err)
		}
		isTrue := ifCond.True(r)
		if isTrue != test.isTrue {
			t.Errorf("Test %v: expected %v found %v", i, test.isTrue, isTrue)
		}
	}
}
