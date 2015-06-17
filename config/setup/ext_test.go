package setup

import (
	"testing"

	"github.com/mholt/caddy/middleware/extensions"
)

func TestExt(t *testing.T) {
	c := newTestController(`ext .html .htm .php`)

	mid, err := Ext(c)

	if err != nil {
		t.Errorf("Expected no errors, got: %v", err)
	}

	if mid == nil {
		t.Fatal("Expected middleware, was nil instead")
	}

	handler := mid(emptyNext)
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
	if !sameNext(myHandler.Next, emptyNext) {
		t.Error("'Next' field of handler was not set properly")
	}

}
