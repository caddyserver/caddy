package setup

import (
	"fmt"
	"regexp"
	"testing"

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
			rewrite.SimpleRule{From: "/from", To: "/to"},
		}},
		{`rewrite /from /to
		  rewrite a b`, false, []rewrite.Rule{
			rewrite.SimpleRule{From: "/from", To: "/to"},
			rewrite.SimpleRule{From: "a", To: "b"},
		}},
		{`rewrite a`, true, []rewrite.Rule{}},
		{`rewrite`, true, []rewrite.Rule{}},
		{`rewrite a b c`, false, []rewrite.Rule{
			rewrite.SimpleRule{From: "a", To: "b c"},
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
			to	/to /index.php?
		 }`, false, []rewrite.Rule{
			&rewrite.ComplexRule{Base: "/", To: "/to /index.php?", Regexp: regexp.MustCompile(".*")},
		}},
		{`rewrite {
			regexp	.*
			to		/to
			ext		/ html txt
		 }`, false, []rewrite.Rule{
			&rewrite.ComplexRule{Base: "/", To: "/to", Exts: []string{"/", "html", "txt"}, Regexp: regexp.MustCompile(".*")},
		}},
		{`rewrite /path {
			r	rr
			to	/dest
		 }
		 rewrite / {
		 	regexp	[a-z]+
		 	to 		/to /to2
		 }
		 `, false, []rewrite.Rule{
			&rewrite.ComplexRule{Base: "/path", To: "/dest", Regexp: regexp.MustCompile("rr")},
			&rewrite.ComplexRule{Base: "/", To: "/to /to2", Regexp: regexp.MustCompile("[a-z]+")},
		}},
		{`rewrite {
			r	.*
		 }`, true, []rewrite.Rule{
			&rewrite.ComplexRule{},
		}},
		{`rewrite {

		 }`, true, []rewrite.Rule{
			&rewrite.ComplexRule{},
		}},
		{`rewrite /`, true, []rewrite.Rule{
			&rewrite.ComplexRule{},
		}},
		{`rewrite {
			to	/to
			if {path} is a
		 }`, false, []rewrite.Rule{
			&rewrite.ComplexRule{Base: "/", To: "/to", Ifs: []rewrite.If{{A: "{path}", Operator: "is", B: "a"}}},
		}},
		{`rewrite {
			status 500
		 }`, true, []rewrite.Rule{
			&rewrite.ComplexRule{},
		}},
		{`rewrite {
			status 400
		 }`, false, []rewrite.Rule{
			&rewrite.ComplexRule{Base: "/", Status: 400},
		}},
		{`rewrite {
			to /to
			status 400
		 }`, false, []rewrite.Rule{
			&rewrite.ComplexRule{Base: "/", To: "/to", Status: 400},
		}},
		{`rewrite {
			status 399
		 }`, true, []rewrite.Rule{
			&rewrite.ComplexRule{},
		}},
		{`rewrite {
			status 200
		 }`, false, []rewrite.Rule{
			&rewrite.ComplexRule{Base: "/", Status: 200},
		}},
		{`rewrite {
			to /to
			status 200
		 }`, false, []rewrite.Rule{
			&rewrite.ComplexRule{Base: "/", To: "/to", Status: 200},
		}},
		{`rewrite {
			status 199
		 }`, true, []rewrite.Rule{
			&rewrite.ComplexRule{},
		}},
		{`rewrite {
			status 0
		 }`, true, []rewrite.Rule{
			&rewrite.ComplexRule{},
		}},
		{`rewrite {
			to /to
			status 0
		 }`, true, []rewrite.Rule{
			&rewrite.ComplexRule{},
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
			actualRule := actual[j].(*rewrite.ComplexRule)
			expectedRule := e.(*rewrite.ComplexRule)

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

			if fmt.Sprint(actualRule.Ifs) != fmt.Sprint(expectedRule.Ifs) {
				t.Errorf("Test %d, rule %d: Expected Pattern=%s, got %s",
					i, j, fmt.Sprint(expectedRule.Ifs), fmt.Sprint(actualRule.Ifs))
			}

		}
	}

}
