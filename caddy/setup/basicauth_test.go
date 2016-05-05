package setup

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"
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
	htpasswdPasswd := "IedFOuGmTpT8"
	htpasswdFile := `sha1:{SHA}dcAUljwz99qFjYR0YLTXx0RqLww=
md5:$apr1$l42y8rex$pOA2VJ0x/0TwaFeAF9nX61`

	var skipHtpassword bool
	htfh, err := ioutil.TempFile(".", "basicauth-")
	if err != nil {
		t.Logf("Error creating temp file (%v), will skip htpassword test", err)
		skipHtpassword = true
	} else {
		if _, err = htfh.Write([]byte(htpasswdFile)); err != nil {
			t.Fatalf("write htpasswd file %q: %v", htfh.Name(), err)
		}
		htfh.Close()
		defer os.Remove(htfh.Name())
	}

	tests := []struct {
		input     string
		shouldErr bool
		password  string
		expected  []basicauth.Rule
	}{
		{`basicauth user pwd`, false, "pwd", []basicauth.Rule{
			{Username: "user"},
		}},
		{`basicauth user pwd {
		}`, false, "pwd", []basicauth.Rule{
			{Username: "user"},
		}},
		{`basicauth user pwd {
			/resource1
			/resource2
		}`, false, "pwd", []basicauth.Rule{
			{Username: "user", Resources: []string{"/resource1", "/resource2"}},
		}},
		{`basicauth /resource user pwd`, false, "pwd", []basicauth.Rule{
			{Username: "user", Resources: []string{"/resource"}},
		}},
		{`basicauth /res1 user1 pwd1
		  basicauth /res2 user2 pwd2`, false, "pwd", []basicauth.Rule{
			{Username: "user1", Resources: []string{"/res1"}},
			{Username: "user2", Resources: []string{"/res2"}},
		}},
		{`basicauth user`, true, "", []basicauth.Rule{}},
		{`basicauth`, true, "", []basicauth.Rule{}},
		{`basicauth /resource user pwd asdf`, true, "", []basicauth.Rule{}},

		{`basicauth sha1 htpasswd=` + htfh.Name(), false, htpasswdPasswd, []basicauth.Rule{
			{Username: "sha1"},
		}},
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

			if strings.Contains(test.input, "htpasswd=") && skipHtpassword {
				continue
			}
			pwd := test.password
			if len(actual) > 1 {
				pwd = fmt.Sprintf("%s%d", pwd, j+1)
			}
			if !actualRule.Password(pwd) || actualRule.Password(test.password+"!") {
				t.Errorf("Test %d, rule %d: Expected password '%v', got '%v'",
					i, j, test.password, actualRule.Password(""))
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
