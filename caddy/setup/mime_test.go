package setup

import (
	"testing"

	"github.com/mholt/caddy/middleware/mime"
)

func TestMime(t *testing.T) {

	c := NewTestController(`mime .txt text/plain`)

	mid, err := Mime(c)
	if err != nil {
		t.Errorf("Expected no errors, but got: %v", err)
	}
	if mid == nil {
		t.Fatal("Expected middleware, was nil instead")
	}

	handler := mid(EmptyNext)
	myHandler, ok := handler.(mime.Mime)
	if !ok {
		t.Fatalf("Expected handler to be type Mime, got: %#v", handler)
	}

	if !SameNext(myHandler.Next, EmptyNext) {
		t.Error("'Next' field of handler was not set properly")
	}

	tests := []struct {
		input     string
		shouldErr bool
	}{
		{`mime {`, true},
		{`mime {}`, true},
		{`mime a b`, true},
		{`mime a {`, true},
		{`mime { txt f } `, true},
		{`mime { html } `, true},
		{`mime {
		 .html text/html
		 .txt text/plain
		} `, false},
		{`mime {
		 .foo text/foo
		 .bar text/bar
		 .foo text/foobar
		} `, true},
		{`mime { .html text/html } `, false},
		{`mime { .html
		} `, true},
		{`mime .txt text/plain`, false},
	}
	for i, test := range tests {
		c := NewTestController(test.input)
		m, err := mimeParse(c)
		if test.shouldErr && err == nil {
			t.Errorf("Test %v: Expected error but found nil %v", i, m)
		} else if !test.shouldErr && err != nil {
			t.Errorf("Test %v: Expected no error but found error: %v", i, err)
		}
	}
}
