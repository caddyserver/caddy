package setup

import (
	"fmt"
	"testing"

	"github.com/mholt/caddy/middleware/headers"
)

func TestHeaders(t *testing.T) {
	c := NewTestController(`header / Foo Bar`)

	mid, err := Headers(c)
	if err != nil {
		t.Errorf("Expected no errors, but got: %v", err)
	}
	if mid == nil {
		t.Fatal("Expected middleware, was nil instead")
	}

	handler := mid(EmptyNext)
	myHandler, ok := handler.(headers.Headers)
	if !ok {
		t.Fatalf("Expected handler to be type Headers, got: %#v", handler)
	}

	if !SameNext(myHandler.Next, EmptyNext) {
		t.Error("'Next' field of handler was not set properly")
	}
}

func TestHeadersParse(t *testing.T) {
	tests := []struct {
		input     string
		shouldErr bool
		expected  []headers.Rule
	}{
		{`header /foo Foo "Bar Baz"`,
			false, []headers.Rule{
				{Path: "/foo", Headers: []headers.Header{
					{"Foo", "Bar Baz"},
				}},
			}},
		{`header /bar { Foo "Bar Baz" Baz Qux }`,
			false, []headers.Rule{
				{Path: "/bar", Headers: []headers.Header{
					{"Foo", "Bar Baz"},
					{"Baz", "Qux"},
				}},
			}},
	}

	for i, test := range tests {
		c := NewTestController(test.input)
		actual, err := headersParse(c)

		if err == nil && test.shouldErr {
			t.Errorf("Test %d didn't error, but it should have", i)
		} else if err != nil && !test.shouldErr {
			t.Errorf("Test %d errored, but it shouldn't have; got '%v'", i, err)
		}

		if len(actual) != len(test.expected) {
			t.Fatalf("Test %d expected %d rules, but got %d",
				i, len(test.expected), len(actual))
		}

		for j, expectedRule := range test.expected {
			actualRule := actual[j]

			if actualRule.Path != expectedRule.Path {
				t.Errorf("Test %d, rule %d: Expected path %s, but got %s",
					i, j, expectedRule.Path, actualRule.Path)
			}

			expectedHeaders := fmt.Sprintf("%v", expectedRule.Headers)
			actualHeaders := fmt.Sprintf("%v", actualRule.Headers)

			if actualHeaders != expectedHeaders {
				t.Errorf("Test %d, rule %d: Expected headers %s, but got %s",
					i, j, expectedHeaders, actualHeaders)
			}
		}
	}
}
