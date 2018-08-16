package digestauth

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
	c := caddy.NewTestController("http", `digestauth user pwd`)
	err := setup(c)
	if err != nil {
		t.Errorf("Expected no errors, but got: %v", err)
	}
	mids := httpserver.GetConfig(c).Middleware()
	if len(mids) == 0 {
		t.Fatal("Expected middleware, got 0 instead")
	}

	handler := mids[0](httpserver.EmptyNext)
	myHandler, ok := handler.(DigestAuth)
	if !ok {
		t.Fatalf("Expected handler to be type DigestAuth, got: %#v", handler)
	}

	if !httpserver.SameNext(myHandler.Next, httpserver.EmptyNext) {
		t.Error("'Next' field of handler was not set properly")
	}
}

func TestDigestAuthParse(t *testing.T) {
	//htpasswdPasswd := "IedFOuGmTpT8"
	htpasswdFile := `sha1:{SHA}dcAUljwz99qFjYR0YLTXx0RqLww=
md5:$apr1$l42y8rex$pOA2VJ0x/0TwaFeAF9nX61`

	var skipHtpassword bool
	htfh, err := ioutil.TempFile(".", "digestauth-")
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
		{`digestauth user pwd`, false, "pwd", []Rule{
			{Users: NewSimpleUserStore(map[string]string{"user": "pwd"})},
		}},
		{`digestauth user pwd {
		}`, false, "pwd", []Rule{
			{Users: NewSimpleUserStore(map[string]string{"user": "pwd"})},
		}},
		{`digestauth /resource1 user pwd {
		}`, false, "pwd", []Rule{
			{Users: NewSimpleUserStore(map[string]string{"user": "pwd"}),
				Resources: []string{"/resource1"}, Realm: "Restricted"},
		}},
		{`digestauth /resource1 user pwd {
			realm Resources
		}`, false, "pwd", []Rule{
			{Users: NewSimpleUserStore(map[string]string{"user": "pwd"}),
				Resources: []string{"/resource1"}, Realm: "Resources"},
		}},
		{`digestauth user pwd {
			/resource1
			/resource2
		}`, false, "pwd", []Rule{
			{Users: NewSimpleUserStore(map[string]string{"user": "pwd"}),
				Resources: []string{"/resource1", "/resource2"}, Realm: "Restricted"},
		}},
		{`digestauth user pwd {
			/resource1
			/resource2
			realm "Secure resources"
		}`, false, "pwd", []Rule{
			{Users: NewSimpleUserStore(map[string]string{"user": "pwd"}),
				Resources: []string{"/resource1", "/resource2"}, Realm: "Secure resources"},
		}},
		{`digestauth user pwd {
			/resource1
			realm "Secure resources"
			realm Extra
			/resource2
		}`, true, "pwd", []Rule{}},
		{`digestauth user pwd {
			/resource1
			foo "Resources"
			/resource2
		}`, true, "pwd", []Rule{}},
		{`digestauth /resource user pwd`, false, "pwd", []Rule{
			{Users: NewSimpleUserStore(map[string]string{"user": "pwd"}), Realm: "Restricted"},
		}},
		{`digestauth /res1 user1 pwd1
		  digestauth /res2 user2 pwd2`, false, "pwd", []Rule{
			{Users: NewSimpleUserStore(map[string]string{"user1": "pwd1"}),
				Resources: []string{"/res1"}, Realm: "Restricted"},
			{Users: NewSimpleUserStore(map[string]string{"user2": "pwd2"}),
				Resources: []string{"/res2"}, Realm: "Restricted"},
		}},
		{`digestauth user`, true, "", []Rule{}},
		{`digestauth`, true, "", []Rule{}},
		{`digestauth /resource user pwd asdf`, true, "", []Rule{}},

		//{`digestauth sha1 htpasswd=` + htfh.Name(), false, htpasswdPasswd, []Rule{
		//{Users: NewHtdigestUserStore(htfh.Name(), nil),
		//Resources: []string{"/res2"}, Realm: "Restricted"},
		//}},
	}

	for i, test := range tests {
		actual, err := digestAuthParse(caddy.NewTestController("http", test.input))

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

			if actualRule.Users != expectedRule.Users {
				t.Errorf("Test %d, rule %d: Expected username '%s', got '%s'",
					i, j, expectedRule.Users, actualRule.Users)
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
			//if !actualRule.Password(pwd) || actualRule.Password(test.password+"!") {
			//t.Errorf("Test %d, rule %d: Expected password '%v', got '%v'",
			//i, j, test.password, actualRule.Password(""))
			//}

			expectedRes := fmt.Sprintf("%v", expectedRule.Resources)
			actualRes := fmt.Sprintf("%v", actualRule.Resources)
			if actualRes != expectedRes {
				t.Errorf("Test %d, rule %d: Expected resource list %s, but got %s",
					i, j, expectedRes, actualRes)
			}
		}
	}
}
