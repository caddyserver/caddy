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

package basicauth

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func TestSetup(t *testing.T) {
	c := caddy.NewTestController("http", `basicauth user pwd`)
	err := setup(c)
	if err != nil {
		t.Errorf("Expected no errors, but got: %v", err)
	}
	mids := httpserver.GetConfig(c).Middleware()
	if len(mids) == 0 {
		t.Fatal("Expected middleware, got 0 instead")
	}

	handler := mids[0](httpserver.EmptyNext)
	myHandler, ok := handler.(BasicAuth)
	if !ok {
		t.Fatalf("Expected handler to be type BasicAuth, got: %#v", handler)
	}

	if !httpserver.SameNext(myHandler.Next, httpserver.EmptyNext) {
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
		expected  []Rule
	}{
		{`basicauth user pwd`, false, "pwd", []Rule{
			{Username: "user"},
		}},
		{`basicauth user pwd {
		}`, false, "pwd", []Rule{
			{Username: "user"},
		}},
		{`basicauth /resource1 user pwd {
		}`, false, "pwd", []Rule{
			{Username: "user", Resources: []string{"/resource1"}},
		}},
		{`basicauth /resource1 user pwd {
			realm Resources
		}`, false, "pwd", []Rule{
			{Username: "user", Resources: []string{"/resource1"}, Realm: "Resources"},
		}},
		{`basicauth user pwd {
			/resource1
			/resource2
		}`, false, "pwd", []Rule{
			{Username: "user", Resources: []string{"/resource1", "/resource2"}},
		}},
		{`basicauth user pwd {
			/resource1
			/resource2
			realm "Secure resources"
		}`, false, "pwd", []Rule{
			{Username: "user", Resources: []string{"/resource1", "/resource2"}, Realm: "Secure resources"},
		}},
		{`basicauth user pwd {
			/resource1
			realm "Secure resources"
			realm Extra
			/resource2
		}`, true, "pwd", []Rule{}},
		{`basicauth user pwd {
			/resource1
			foo "Resources"
			/resource2
		}`, true, "pwd", []Rule{}},
		{`basicauth /resource user pwd`, false, "pwd", []Rule{
			{Username: "user", Resources: []string{"/resource"}},
		}},
		{`basicauth /res1 user1 pwd1
		  basicauth /res2 user2 pwd2`, false, "pwd", []Rule{
			{Username: "user1", Resources: []string{"/res1"}},
			{Username: "user2", Resources: []string{"/res2"}},
		}},
		{`basicauth user`, true, "", []Rule{}},
		{`basicauth`, true, "", []Rule{}},
		{`basicauth /resource user pwd asdf`, true, "", []Rule{}},

		{`basicauth sha1 htpasswd=` + htfh.Name(), false, htpasswdPasswd, []Rule{
			{Username: "sha1"},
		}},
	}

	for i, test := range tests {
		actual, err := basicAuthParse(caddy.NewTestController("http", test.input))

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

			if actualRule.Realm != expectedRule.Realm {
				t.Errorf("Test %d, rule %d: Expected realm '%s', got '%s'",
					i, j, expectedRule.Realm, actualRule.Realm)
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
