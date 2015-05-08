package setup

import (
	"testing"

	"github.com/mholt/caddy/middleware/rewrite"
)

func TestRewrite(t *testing.T) {
	c := newTestController(`rewrite /from /to`)

	mid, err := Rewrite(c)
	if err != nil {
		t.Errorf("Expected no errors, but got: %v", err)
	}
	if mid == nil {
		t.Fatal("Expected middleware, was nil instead")
	}

	handler := mid(emptyNext)
	myHandler, ok := handler.(rewrite.Rewrite)
	if !ok {
		t.Fatalf("Expected handler to be type Rewrite, got: %#v", handler)
	}

	if !sameNext(myHandler.Next, emptyNext) {
		t.Error("'Next' field of handler was not set properly")
	}

	if len(myHandler.Rules) != 1 {
		t.Errorf("Expected handler to have %d rule, has %d instead", 1, len(myHandler.Rules))
	}
}

func TestRewriteParse(t *testing.T) {
	tests := []struct {
		input     string
		shouldErr bool
		expected  []rewrite.Rule
	}{
		{`rewrite /from /to`, false, []rewrite.Rule{
			{From: "/from", To: "/to"},
		}},
		{`rewrite /from /to
		  rewrite a b`, false, []rewrite.Rule{
			{From: "/from", To: "/to"},
			{From: "a", To: "b"},
		}},
		{`rewrite a`, true, []rewrite.Rule{}},
		{`rewrite`, true, []rewrite.Rule{}},
		{`rewrite a b c`, true, []rewrite.Rule{
			{From: "a", To: "b"},
		}},
	}

	for i, test := range tests {
		c := newTestController(test.input)
		actual, err := rewriteParse(c)

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
}
