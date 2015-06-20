package setup

import (
	"fmt"
	"testing"

	"github.com/mholt/caddy/middleware/basicauth"
)

func TestBasicAuth(t *testing.T) {
	c := NewTestController(`basicauth user pwd`)

	mid, err := BasicAuth(c)
	if err != nil {
		t.Errorf("Expected no errors, but got: %v", err)
	}
	if mid == nil {
		t.Fatal("Expected middleware, was nil instead")
	}

	handler := mid(EmptyNext)
	myHandler, ok := handler.(basicauth.BasicAuth)
	if !ok {
		t.Fatalf("Expected handler to be type BasicAuth, got: %#v", handler)
	}

	if !SameNext(myHandler.Next, EmptyNext) {
		t.Error("'Next' field of handler was not set properly")
	}
}

func TestBasicAuthParse(t *testing.T) {
	tests := []struct {
		input     string
		shouldErr bool
		expected  []basicauth.Rule
	}{
		{`basicauth user pwd`, false, []basicauth.Rule{
			{Username: "user", Password: "pwd"},
		}},
		{`basicauth user pwd {
		}`, false, []basicauth.Rule{
			{Username: "user", Password: "pwd"},
		}},
		{`basicauth user pwd {
			/resource1
			/resource2
		}`, false, []basicauth.Rule{
			{Username: "user", Password: "pwd", Resources: []string{"/resource1", "/resource2"}},
		}},
		{`basicauth /resource user pwd`, false, []basicauth.Rule{
			{Username: "user", Password: "pwd", Resources: []string{"/resource"}},
		}},
		{`basicauth /res1 user1 pwd1
		  basicauth /res2 user2 pwd2`, false, []basicauth.Rule{
			{Username: "user1", Password: "pwd1", Resources: []string{"/res1"}},
			{Username: "user2", Password: "pwd2", Resources: []string{"/res2"}},
		}},
		{`basicauth user`, true, []basicauth.Rule{}},
		{`basicauth`, true, []basicauth.Rule{}},
		{`basicauth /resource user pwd asdf`, true, []basicauth.Rule{}},
	}

	for i, test := range tests {
		c := NewTestController(test.input)
		actual, err := basicAuthParse(c)

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

			if actualRule.Username != expectedRule.Username {
				t.Errorf("Test %d, rule %d: Expected username '%s', got '%s'",
					i, j, expectedRule.Username, actualRule.Username)
			}

			if actualRule.Password != expectedRule.Password {
				t.Errorf("Test %d, rule %d: Expected password '%s', got '%s'",
					i, j, expectedRule.Password, actualRule.Password)
			}

			expectedRes := fmt.Sprintf("%v", expectedRule.Resources)
			actualRes := fmt.Sprintf("%v", actualRule.Resources)
			if actualRes != expectedRes {
				t.Errorf("Test %d, rule %d: Expected resource list %s, but got %s",
					i, j, expectedRes, actualRes)
			}
		}
	}
}
