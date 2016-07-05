package mime

import (
	"testing"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func TestSetup(t *testing.T) {
	c := caddy.NewTestController("http", `mime .txt text/plain`)
	err := setup(c)
	if err != nil {
		t.Errorf("Expected no errors, but got: %v", err)
	}
	mids := httpserver.GetConfig(c).Middleware()
	if len(mids) == 0 {
		t.Fatal("Expected middleware, but had 0 instead")
	}

	handler := mids[0](httpserver.EmptyNext)
	myHandler, ok := handler.(Mime)
	if !ok {
		t.Fatalf("Expected handler to be type Mime, got: %#v", handler)
	}

	if !httpserver.SameNext(myHandler.Next, httpserver.EmptyNext) {
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
		m, err := mimeParse(caddy.NewTestController("http", test.input))
		if test.shouldErr && err == nil {
			t.Errorf("Test %v: Expected error but found nil %v", i, m)
		} else if !test.shouldErr && err != nil {
			t.Errorf("Test %v: Expected no error but found error: %v", i, err)
		}
	}
}
