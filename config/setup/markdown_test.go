package setup

import (
	"github.com/mholt/caddy/middleware/markdown"
	"testing"
)

func TestMarkdown(t *testing.T) {

	c := NewTestController(`markdown /blog`)

	mid, err := Markdown(c)

	if err != nil {
		t.Errorf("Expected no errors, got: %v", err)
	}

	if mid == nil {
		t.Fatal("Expected middleware, was nil instead")
	}

	handler := mid(EmptyNext)
	myHandler, ok := handler.(markdown.Markdown)

	if !ok {
		t.Fatalf("Expected handler to be type Markdown, got: %#v", handler)
	}

	if myHandler.Configs[0].PathScope != "/blog" {
		t.Errorf("Expected /blog as the Path Scope")
	}

}
