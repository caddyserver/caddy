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

	if myHandler.Rules[0].Path != defaultTemplatePath {
		t.Errorf("Expected / as the default Path")
	}
	if fmt.Sprint(myHandler.Rules[0].Extensions) != fmt.Sprint(defaultTemplateExtensions) {
		t.Errorf("Expected %v to be the Default Extensions", defaultTemplateExtensions)
	}
	var indexFiles []string
	for _, extension := range defaultTemplateExtensions {
		indexFiles = append(indexFiles, "index"+extension)
	}
	if fmt.Sprint(myHandler.Rules[0].IndexFiles) != fmt.Sprint(indexFiles) {
		t.Errorf("Expected %v to be the Default Index files", indexFiles)
	}
}
func TestTemplatesParse(t *testing.T) {
	tests := []struct {
		inputTemplateConfig    string
		shouldErr              bool
		expectedTemplateConfig []templates.Rule
	}{
		{`templates /api1`, false, []templates.Rule{{
			Path:       "/api1",
			Extensions: defaultTemplateExtensions,
		}}},
		{`templates /api2 .txt .htm`, false, []templates.Rule{{
			Path:       "/api2",
			Extensions: []string{".txt", ".htm"},
		}}},

		{`templates /api3 .htm .html  
		  templates /api4 .txt .tpl `, false, []templates.Rule{{
			Path:       "/api3",
			Extensions: []string{".htm", ".html"},
		}, {
			Path:       "/api4",
			Extensions: []string{".txt", ".tpl"},
		}}},
	}
	for i, test := range tests {
		c := NewTestController(test.inputTemplateConfig)
		actualTemplateConfigs, err := templatesParse(c)

		if err == nil && test.shouldErr {
			t.Errorf("Test %d didn't error, but it should have", i)
		} else if err != nil && !test.shouldErr {
			t.Errorf("Test %d errored, but it shouldn't have; got '%v'", i, err)
		}
		if len(actualTemplateConfigs) != len(test.expectedTemplateConfig) {
			t.Fatalf("Test %d expected %d no of Template configs, but got %d ",
				i, len(test.expectedTemplateConfig), len(actualTemplateConfigs))
		}
		for j, actualTemplateConfig := range actualTemplateConfigs {

			if actualTemplateConfig.Path != test.expectedTemplateConfig[j].Path {
				t.Errorf("Test %d expected %dth Template Config Path to be  %s  , but got %s",
					i, j, test.expectedTemplateConfig[j].Path, actualTemplateConfig.Path)
			}

			if fmt.Sprint(actualTemplateConfig.Extensions) != fmt.Sprint(test.expectedTemplateConfig[j].Extensions) {
				t.Errorf("Expected %v to be the  Extensions , but got %v instead", test.expectedTemplateConfig[j].Extensions, actualTemplateConfig.Extensions)
			}
		}
	}

}
