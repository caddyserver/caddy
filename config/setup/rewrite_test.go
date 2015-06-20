package setup

import (
	"testing"

	"fmt"
	"regexp"

	"github.com/mholt/caddy/middleware/rewrite"
)

func TestRewrite(t *testing.T) {
	c := NewTestController(`rewrite /from /to`)

	mid, err := Rewrite(c)
	if err != nil {
		t.Errorf("Expected no errors, but got: %v", err)
	}
	if mid == nil {
		t.Fatal("Expected middleware, was nil instead")
	}

	handler := mid(EmptyNext)
	myHandler, ok := handler.(rewrite.Rewrite)
	if !ok {
		t.Fatalf("Expected handler to be type Rewrite, got: %#v", handler)
	}

	if !SameNext(myHandler.Next, EmptyNext) {
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
		expected  []rewrite.Rule
	}{
		{`rewrite /from /to`, false, []rewrite.Rule{
			rewrite.SimpleRule{"/from", "/to"},
		}},
		{`rewrite /from /to
		  rewrite a b`, false, []rewrite.Rule{
			rewrite.SimpleRule{"/from", "/to"},
			rewrite.SimpleRule{"a", "b"},
		}},
		{`rewrite a`, true, []rewrite.Rule{}},
		{`rewrite`, true, []rewrite.Rule{}},
		{`rewrite a b c`, true, []rewrite.Rule{
			rewrite.SimpleRule{"a", "b"},
		}},
	}

	for i, test := range simpleTests {
		c := NewTestController(test.input)
		actual, err := rewriteParse(c)

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
			actualRule := actual[j].(rewrite.SimpleRule)
			expectedRule := e.(rewrite.SimpleRule)

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
		expected  []rewrite.Rule
	}{
		{`rewrite {
			r	.*
			to	/to
		 }`, false, []rewrite.Rule{
			&rewrite.RegexpRule{"/", "/to", nil, regexp.MustCompile(".*")},
		}},
		{`rewrite {
			regexp	.*
			to		/to
			ext		/ html txt
		 }`, false, []rewrite.Rule{
			&rewrite.RegexpRule{"/", "/to", []string{"/", "html", "txt"}, regexp.MustCompile(".*")},
		}},
		{`rewrite /path {
			r	rr
			to	/dest
		 }
		 rewrite / {
		 	regexp	[a-z]+
		 	to 		/to
		 }
		 `, false, []rewrite.Rule{
			&rewrite.RegexpRule{"/path", "/dest", nil, regexp.MustCompile("rr")},
			&rewrite.RegexpRule{"/", "/to", nil, regexp.MustCompile("[a-z]+")},
		}},
		{`rewrite {
			to	/to
		 }`, true, []rewrite.Rule{
			&rewrite.RegexpRule{},
		}},
		{`rewrite {
			r	.*
		 }`, true, []rewrite.Rule{
			&rewrite.RegexpRule{},
		}},
		{`rewrite {

		 }`, true, []rewrite.Rule{
			&rewrite.RegexpRule{},
		}},
		{`rewrite /`, true, []rewrite.Rule{
			&rewrite.RegexpRule{},
		}},
	}

	for i, test := range regexpTests {
		c := NewTestController(test.input)
		actual, err := rewriteParse(c)

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
			actualRule := actual[j].(*rewrite.RegexpRule)
			expectedRule := e.(*rewrite.RegexpRule)

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

			if actualRule.String() != expectedRule.String() {
				t.Errorf("Test %d, rule %d: Expected Pattern=%s, got %s",
					i, j, expectedRule.String(), actualRule.String())
			}
		}
	}

}
