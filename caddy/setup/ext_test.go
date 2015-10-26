package setup

import (
	"testing"

	"github.com/mholt/caddy/middleware/extensions"
)

func TestExt(t *testing.T) {
	c := NewTestController(`ext .html .htm .php`)

	mid, err := Ext(c)

	if err != nil {
		t.Errorf("Expected no errors, got: %v", err)
	}

	if mid == nil {
		t.Fatal("Expected middleware, was nil instead")
	}

	handler := mid(EmptyNext)
	myHandler, ok := handler.(extensions.Ext)

	if !ok {
		t.Fatalf("Expected handler to be type Ext, got: %#v", handler)
	}

	if myHandler.Extensions[0] != ".html" {
		t.Errorf("Expected .html in the list of Extensions")
	}
	if myHandler.Extensions[1] != ".htm" {
		t.Errorf("Expected .htm in the list of Extensions")
	}
	if myHandler.Extensions[2] != ".php" {
		t.Errorf("Expected .php in the list of Extensions")
	}
	if !SameNext(myHandler.Next, EmptyNext) {
		t.Error("'Next' field of handler was not set properly")
	}

}

func TestExtParse(t *testing.T) {
	tests := []struct {
		inputExts    string
		shouldErr    bool
		expectedExts []string
	}{
		{`ext .html .htm .php`, false, []string{".html", ".htm", ".php"}},
		{`ext .php .html .xml`, false, []string{".php", ".html", ".xml"}},
		{`ext .txt .php .xml`, false, []string{".txt", ".php", ".xml"}},
	}
	for i, test := range tests {
		c := NewTestController(test.inputExts)
		actualExts, err := extParse(c)

		if err == nil && test.shouldErr {
			t.Errorf("Test %d didn't error, but it should have", i)
		} else if err != nil && !test.shouldErr {
			t.Errorf("Test %d errored, but it shouldn't have; got '%v'", i, err)
		}

		if len(actualExts) != len(test.expectedExts) {
			t.Fatalf("Test %d expected %d rules, but got %d",
				i, len(test.expectedExts), len(actualExts))
		}
		for j, actualExt := range actualExts {
			if actualExt != test.expectedExts[j] {
				t.Fatalf("Test %d expected %dth extension to be  %s  , but got %s",
					i, j, test.expectedExts[j], actualExt)
			}
		}
	}

}
