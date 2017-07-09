package requestid

import (
	"testing"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func TestSetup(t *testing.T) {
	c := caddy.NewTestController("http", `requestid`)
	err := setup(c)
	if err != nil {
		t.Errorf("Expected no errors, got: %v", err)
	}
	mids := httpserver.GetConfig(c).Middleware()
	if len(mids) == 0 {
		t.Fatal("Expected middleware, got 0 instead")
	}

	handler := mids[0](httpserver.EmptyNext)
	myHandler, ok := handler.(Handler)

	if !ok {
		t.Fatalf("Expected handler to be type Handler, got: %#v", handler)
	}

	if !httpserver.SameNext(myHandler.Next, httpserver.EmptyNext) {
		t.Error("'Next' field of handler was not set properly")
	}
}

func TestSetupWithArg(t *testing.T) {
	c := caddy.NewTestController("http", `requestid abc`)
	err := setup(c)
	if err == nil {
		t.Errorf("Expected an error, got: %v", err)
	}
	mids := httpserver.GetConfig(c).Middleware()
	if len(mids) != 0 {
		t.Fatal("Expected no middleware")
	}
}
