package setup

import (
	"github.com/mholt/caddy/middleware/fastcgi"
	"testing"
)

func TestFastCGI(t *testing.T) {

	c := NewTestController(`fastcgi / 127.0.0.1:9000`)

	mid, err := FastCGI(c)

	if err != nil {
		t.Errorf("Expected no errors, got: %v", err)
	}

	if mid == nil {
		t.Fatal("Expected middleware, was nil instead")
	}

	handler := mid(EmptyNext)
	myHandler, ok := handler.(fastcgi.Handler)

	if !ok {
		t.Fatalf("Expected handler to be type , got: %#v", handler)
	}

	if myHandler.Rules[0].Path != "/" {
		t.Errorf("Expected / as the Path")
	}
	if myHandler.Rules[0].Address != "127.0.0.1:9000" {
		t.Errorf("Expected 127.0.0.1:9000 as the Address")
	}

}
