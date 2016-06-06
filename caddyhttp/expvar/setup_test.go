package expvar

import (
	"testing"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func TestSetup(t *testing.T) {
	err := setup(caddy.NewTestController(`expvar`))
	if err != nil {
		t.Errorf("Expected no errors, got: %v", err)
	}
	mids := httpserver.GetConfig("").Middleware()
	if len(mids) == 0 {
		t.Fatal("Expected middleware, got 0 instead")
	}

	err = setup(caddy.NewTestController(`expvar /d/v`))
	if err != nil {
		t.Errorf("Expected no errors, got: %v", err)
	}
	mids = httpserver.GetConfig("").Middleware()
	if len(mids) == 0 {
		t.Fatal("Expected middleware, got 0 instead")
	}

	handler := mids[1](httpserver.EmptyNext)
	myHandler, ok := handler.(ExpVar)
	if !ok {
		t.Fatalf("Expected handler to be type ExpVar, got: %#v", handler)
	}
	if myHandler.Resource != "/d/v" {
		t.Errorf("Expected /d/v as expvar resource")
	}
	if !httpserver.SameNext(myHandler.Next, httpserver.EmptyNext) {
		t.Error("'Next' field of handler was not set properly")
	}
}
