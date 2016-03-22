package setup

import (
	"testing"

	"github.com/mholt/caddy/middleware/expvar"
)

func TestExpvar(t *testing.T) {
	c := NewTestController(`expvar /d/v`)

	mid, err := ExpVar(c)

	if err != nil {
		t.Errorf("Expected no errors, got: %v", err)
	}

	if mid == nil {
		t.Fatal("Expected middleware, was nil instead")
	}

	handler := mid(EmptyNext)
	myHandler, ok := handler.(expvar.ExpVar)

	if !ok {
		t.Fatalf("Expected handler to be type ExpVar, got: %#v", handler)
	}

	if myHandler.Resource != "/d/v" {
		t.Errorf("Expected /d/v as expvar resource")
	}

	if !SameNext(myHandler.Next, EmptyNext) {
		t.Error("'Next' field of handler was not set properly")
	}
}
