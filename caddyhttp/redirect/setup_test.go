package redirect

import (
	"testing"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func TestSetup(t *testing.T) {

	for j, test := range []struct {
		input         string
		shouldErr     bool
		expectedRules []Rule
	}{
		// test case #0 tests the recognition of a valid HTTP status code defined outside of block statement
		{"redir 300 {\n/ /foo\n}", false, []Rule{{FromPath: "/", To: "/foo", Code: 300}}},

		// test case #1 tests the recognition of an invalid HTTP status code defined outside of block statement
		{"redir 9000 {\n/ /foo\n}", true, []Rule{{}}},

		// test case #2 tests the detection of a valid HTTP status code outside of a block statement being overriden by an invalid HTTP status code inside statement of a block statement
		{"redir 300 {\n/ /foo 9000\n}", true, []Rule{{}}},

		// test case #3 tests the detection of an invalid HTTP status code outside of a block statement being overriden by a valid HTTP status code inside statement of a block statement
		{"redir 9000 {\n/ /foo 300\n}", true, []Rule{{}}},

		// test case #4 tests the recognition of a TO redirection in a block statement.The HTTP status code is set to the default of 301 - MovedPermanently
		{"redir 302 {\n/foo\n}", false, []Rule{{FromPath: "/", To: "/foo", Code: 302}}},

		// test case #5 tests the recognition of a TO and From redirection in a block statement
		{"redir {\n/bar /foo 303\n}", false, []Rule{{FromPath: "/bar", To: "/foo", Code: 303}}},

		// test case #6 tests the recognition of a TO redirection in a non-block statement. The HTTP status code is set to the default of 301 - MovedPermanently
		{"redir /foo", false, []Rule{{FromPath: "/", To: "/foo", Code: 301}}},

		// test case #7 tests the recognition of a TO and From redirection in a non-block statement
		{"redir /bar /foo 303", false, []Rule{{FromPath: "/bar", To: "/foo", Code: 303}}},

		// test case #8 tests the recognition of multiple redirections
		{"redir {\n / /foo 304 \n} \n redir {\n /bar /foobar 305 \n}", false, []Rule{{FromPath: "/", To: "/foo", Code: 304}, {FromPath: "/bar", To: "/foobar", Code: 305}}},

		// test case #9 tests the detection of duplicate redirections
		{"redir {\n /bar /foo 304 \n} redir {\n /bar /foo 304 \n}", true, []Rule{{}}},
	} {
		c := caddy.NewTestController("http", test.input)
		err := setup(c)
		if err != nil && !test.shouldErr {
			t.Errorf("Test case #%d recieved an error of %v", j, err)
		} else if test.shouldErr {
			continue
		}
		mids := httpserver.GetConfig(c).Middleware()
		recievedRules := mids[len(mids)-1](nil).(Redirect).Rules

		for i, recievedRule := range recievedRules {
			if recievedRule.FromPath != test.expectedRules[i].FromPath {
				t.Errorf("Test case #%d.%d expected a from path of %s, but recieved a from path of %s", j, i, test.expectedRules[i].FromPath, recievedRule.FromPath)
			}
			if recievedRule.To != test.expectedRules[i].To {
				t.Errorf("Test case #%d.%d expected a TO path of %s, but recieved a TO path of %s", j, i, test.expectedRules[i].To, recievedRule.To)
			}
			if recievedRule.Code != test.expectedRules[i].Code {
				t.Errorf("Test case #%d.%d expected a HTTP status code of %d, but recieved a code of %d", j, i, test.expectedRules[i].Code, recievedRule.Code)
			}
		}
	}

}
