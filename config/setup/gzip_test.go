package setup

import (
	"testing"

	"github.com/mholt/caddy/middleware/gzip"
)

func TestGzip(t *testing.T) {
	c := newTestController(`gzip`)

	mid, err := Gzip(c)
	if err != nil {
		t.Errorf("Expected no errors, but got: %v", err)
	}
	if mid == nil {
		t.Fatal("Expected middleware, was nil instead")
	}

	handler := mid(emptyNext)
	myHandler, ok := handler.(gzip.Gzip)
	if !ok {
		t.Fatalf("Expected handler to be type Gzip, got: %#v", handler)
	}

	if !sameNext(myHandler.Next, emptyNext) {
		t.Error("'Next' field of handler was not set properly")
	}
}
