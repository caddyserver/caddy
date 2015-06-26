package setup

import (
	"fmt"
	"github.com/mholt/caddy/middleware/templates"
	"testing"
)

func TestTemplates(t *testing.T) {

	c := NewTestController(`templates`)

	mid, err := Templates(c)

	if err != nil {
		t.Errorf("Expected no errors, got: %v", err)
	}

	if mid == nil {
		t.Fatal("Expected middleware, was nil instead")
	}

	handler := mid(EmptyNext)
	myHandler, ok := handler.(templates.Templates)

	if !ok {
		t.Fatalf("Expected handler to be type Templates, got: %#v", handler)
	}

	if myHandler.Rules[0].Path != DefaultTemplatePath {
		t.Errorf("Expected / as the default Path")
	}
	if fmt.Sprint(myHandler.Rules[0].Extensions) != fmt.Sprint(DefaultTemplateExtensions) {
		t.Errorf("Expected %v to be the Default Extensions", DefaultTemplateExtensions)
	}
	var indexFiles []string
	for _, extension := range DefaultTemplateExtensions {
		indexFiles = append(indexFiles, "index"+extension)
	}
	if fmt.Sprint(myHandler.Rules[0].IndexFiles) != fmt.Sprint(indexFiles) {
		t.Errorf("Expected %v to be the Default Index files", indexFiles)
	}
}
