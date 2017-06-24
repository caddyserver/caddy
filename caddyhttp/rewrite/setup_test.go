package rewrite

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func TestSetup(t *testing.T) {
	c := caddy.NewTestController("http", `rewrite /from /to`)
	err := setup(c)
	if err != nil {
		t.Errorf("Expected no errors, but got: %v", err)
	}
	mids := httpserver.GetConfig(c).Middleware()
	if len(mids) == 0 {
		t.Fatal("Expected middleware, had 0 instead")
	}

	handler := mids[0](httpserver.EmptyNext)
	myHandler, ok := handler.(Rewrite)
	if !ok {
		t.Fatalf("Expected handler to be type Rewrite, got: %#v", handler)
	}

	if !httpserver.SameNext(myHandler.Next, httpserver.EmptyNext) {
		t.Error("'Next' field of handler was not set properly")
	}

	if len(myHandler.Rules) != 1 {
		t.Errorf("Expected handler to have %d rule, has %d instead", 1, len(myHandler.Rules))
	}
}

func TestRewriteParse(t *testing.T) {
	simpleTests := []struct {
		input     string
		shouldErr bool
		expected  []Rule
	}{
		{`rewrite /from /to`, false, []Rule{
			SimpleRule{From: "/from", To: "/to"},
		}},
		{`rewrite /from /to
		  rewrite a b`, false, []Rule{
			SimpleRule{From: "/from", To: "/to"},
			SimpleRule{From: "a", To: "b"},
		}},
		{`rewrite a`, true, []Rule{}},
		{`rewrite`, true, []Rule{}},
		{`rewrite a b c`, false, []Rule{
			SimpleRule{From: "a", To: "b c"},
		}},
	}

	for i, test := range simpleTests {
		actual, err := rewriteParse(caddy.NewTestController("http", test.input))

		if err == nil && test.shouldErr {
			t.Errorf("Test %d didn't error, but it should have", i)
		} else if err != nil && !test.shouldErr {
			t.Errorf("Test %d errored, but it shouldn't have; got '%v'", i, err)
		} else if err != nil && test.shouldErr {
			continue
		}

		if len(actual) != len(test.expected) {
			t.Fatalf("Test %d expected %d rules, but got %d",
				i, len(test.expected), len(actual))
		}

		for j, e := range test.expected {
			actualRule := actual[j].(SimpleRule)
			expectedRule := e.(SimpleRule)

			if actualRule.From != expectedRule.From {
				t.Errorf("Test %d, rule %d: Expected From=%s, got %s",
					i, j, expectedRule.From, actualRule.From)
			}

			if actualRule.To != expectedRule.To {
				t.Errorf("Test %d, rule %d: Expected To=%s, got %s",
					i, j, expectedRule.To, actualRule.To)
			}
		}
	}

	regexpTests := []struct {
		input     string
		shouldErr bool
		expected  []Rule
	}{
		{`rewrite {
			r	.*
			to	/to /index.php?
		 }`, false, []Rule{
			&ComplexRule{Base: "/", To: "/to /index.php?", Regexp: regexp.MustCompile(".*")},
		}},
		{`rewrite {
			regexp	.*
			to		/to
			ext		/ html txt
		 }`, false, []Rule{
			&ComplexRule{Base: "/", To: "/to", Exts: []string{"/", "html", "txt"}, Regexp: regexp.MustCompile(".*")},
		}},
		{`rewrite /path {
			r	rr
			to	/dest
		 }
		 rewrite / {
		 	regexp	[a-z]+
		 	to 		/to /to2
		 }
		 `, false, []Rule{
			&ComplexRule{Base: "/path", To: "/dest", Regexp: regexp.MustCompile("rr")},
			&ComplexRule{Base: "/", To: "/to /to2", Regexp: regexp.MustCompile("[a-z]+")},
		}},
		{`rewrite {
			r	.*
		 }`, true, []Rule{
			&ComplexRule{},
		}},
		{`rewrite {

		 }`, true, []Rule{
			&ComplexRule{},
		}},
		{`rewrite /`, true, []Rule{
			&ComplexRule{},
		}},
		{`rewrite {
			if {path} match /
			to		/to
		 }`, false, []Rule{
			&ComplexRule{Base: "/", To: "/to"},
		}},
	}

	for i, test := range regexpTests {
		actual, err := rewriteParse(caddy.NewTestController("http", test.input))

		if err == nil && test.shouldErr {
			t.Errorf("Test %d didn't error, but it should have", i)
		} else if err != nil && !test.shouldErr {
			t.Errorf("Test %d errored, but it shouldn't have; got '%v'", i, err)
		} else if err != nil && test.shouldErr {
			continue
		}

		if len(actual) != len(test.expected) {
			t.Fatalf("Test %d expected %d rules, but got %d",
				i, len(test.expected), len(actual))
		}

		for j, e := range test.expected {
			actualRule := actual[j].(*ComplexRule)
			expectedRule := e.(*ComplexRule)

			if actualRule.Base != expectedRule.Base {
				t.Errorf("Test %d, rule %d: Expected Base=%s, got %s",
					i, j, expectedRule.Base, actualRule.Base)
			}

			if actualRule.To != expectedRule.To {
				t.Errorf("Test %d, rule %d: Expected To=%s, got %s",
					i, j, expectedRule.To, actualRule.To)
			}

			if fmt.Sprint(actualRule.Exts) != fmt.Sprint(expectedRule.Exts) {
				t.Errorf("Test %d, rule %d: Expected Ext=%v, got %v",
					i, j, expectedRule.To, actualRule.To)
			}

			if actualRule.Regexp != nil {
				if actualRule.String() != expectedRule.String() {
					t.Errorf("Test %d, rule %d: Expected Pattern=%s, got %s",
						i, j, expectedRule.String(), actualRule.String())
				}
			}

		}
	}

}
