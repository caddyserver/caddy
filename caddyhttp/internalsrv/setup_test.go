package internalsrv

import (
	"testing"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func TestSetup(t *testing.T) {
	c := caddy.NewTestController("http", `internal /internal`)
	err := setup(c)
	if err != nil {
		t.Errorf("Expected no errors, got: %v", err)
	}
	mids := httpserver.GetConfig(c).Middleware()
	if len(mids) == 0 {
		t.Fatal("Expected middleware, got 0 instead")
	}

	handler := mids[0](httpserver.EmptyNext)
	myHandler, ok := handler.(Internal)

	if !ok {
		t.Fatalf("Expected handler to be type Internal, got: %#v", handler)
	}

	if myHandler.Paths[0] != "/internal" {
		t.Errorf("Expected internal in the list of internal Paths")
	}

	if !httpserver.SameNext(myHandler.Next, httpserver.EmptyNext) {
		t.Error("'Next' field of handler was not set properly")
	}

}

func TestInternalParse(t *testing.T) {
	tests := []struct {
		inputInternalPaths    string
		shouldErr             bool
		expectedInternalPaths []string
	}{
		{`internal /internal`, false, []string{"/internal"}},

		{`internal /internal1
		  internal /internal2`, false, []string{"/internal1", "/internal2"}},
	}
	for i, test := range tests {
		actualInternalPaths, err := internalParse(caddy.NewTestController("http", test.inputInternalPaths))

		if err == nil && test.shouldErr {
			t.Errorf("Test %d didn't error, but it should have", i)
		} else if err != nil && !test.shouldErr {
			t.Errorf("Test %d errored, but it shouldn't have; got '%v'", i, err)
		}

		if len(actualInternalPaths) != len(test.expectedInternalPaths) {
			t.Fatalf("Test %d expected %d InternalPaths, but got %d",
				i, len(test.expectedInternalPaths), len(actualInternalPaths))
		}
		for j, actualInternalPath := range actualInternalPaths {
			if actualInternalPath != test.expectedInternalPaths[j] {
				t.Fatalf("Test %d expected %dth Internal Path to be  %s  , but got %s",
					i, j, test.expectedInternalPaths[j], actualInternalPath)
			}
		}
	}

}
