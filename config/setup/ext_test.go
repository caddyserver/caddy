package setup

import (
	"testing"

	"github.com/mholt/caddy/middleware/gzip"
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
	myHandler, ok := handler.(ext.Ext)
	if !ok {
		t.Fatalf("Expected handler to be type Ext, got: %#v", handler)
	}

	if !sameNext(myHandler.Next, emptyNext) {
		t.Error("'Next' field of handler was not set properly")
	}
}