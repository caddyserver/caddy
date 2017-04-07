package index

import (
	"testing"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/staticfiles"
)

func TestIndexIncompleteParams(t *testing.T) {
	c := caddy.NewTestController("", "index")

	err := setupIndex(c)
	if err == nil {
		t.Error("Expected an error, but didn't get one")
	}
}

func TestIndex(t *testing.T) {
	c := caddy.NewTestController("", "index a.html b.html c.html")

	err := setupIndex(c)
	if err != nil {
		t.Errorf("Expected no errors, got: %v", err)
	}

	expectedIndex := []string{"a.html", "b.html", "c.html"}

	if len(staticfiles.IndexPages) != 3 {
		t.Errorf("Expected 3 values, got %v", len(staticfiles.IndexPages))
	}

	// Ensure ordering is correct
	for i, actual := range staticfiles.IndexPages {
		if actual != expectedIndex[i] {
			t.Errorf("Expected value in position %d to be %v, got %v", i, expectedIndex[i], actual)
		}
	}
}
