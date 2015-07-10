package setup

import (
	"fmt"
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
	if fmt.Sprint(myHandler.Configs[0].Extensions) != fmt.Sprint([]string{".md"}) {
		t.Errorf("Expected .md  as the Default Extension")
	}

}
func TestMarkdownParse(t *testing.T) {
	tests := []struct {
		inputMarkdownConfig    string
		shouldErr              bool
		expectedMarkdownConfig []markdown.Config
	}{

		{`markdown /blog {
	ext .md .txt
	css /resources/css/blog.css
	js  /resources/js/blog.js
}`, false, []markdown.Config{{
			PathScope:  "/blog",
			Extensions: []string{".md", ".txt"},
			Styles:     []string{"/resources/css/blog.css"},
			Scripts:    []string{"/resources/js/blog.js"},
		}}},
	}
	for i, test := range tests {
		c := NewTestController(test.inputMarkdownConfig)
		actualMarkdownConfigs, err := markdownParse(c)

		if err == nil && test.shouldErr {
			t.Errorf("Test %d didn't error, but it should have", i)
		} else if err != nil && !test.shouldErr {
			t.Errorf("Test %d errored, but it shouldn't have; got '%v'", i, err)
		}
		if len(actualMarkdownConfigs) != len(test.expectedMarkdownConfig) {
			t.Fatalf("Test %d expected %d no of WebSocket configs, but got %d ",
				i, len(test.expectedMarkdownConfig), len(actualMarkdownConfigs))
		}
		for j, actualMarkdownConfig := range actualMarkdownConfigs {

			if actualMarkdownConfig.PathScope != test.expectedMarkdownConfig[j].PathScope {
				t.Errorf("Test %d expected %dth Markdown PathScope to be  %s  , but got %s",
					i, j, test.expectedMarkdownConfig[j].PathScope, actualMarkdownConfig.PathScope)
			}

			if fmt.Sprint(actualMarkdownConfig.Styles) != fmt.Sprint(test.expectedMarkdownConfig[j].Styles) {
				t.Errorf("Test %d expected %dth Markdown Config Styles to be  %s  , but got %s",
					i, j, fmt.Sprint(test.expectedMarkdownConfig[j].Styles), fmt.Sprint(actualMarkdownConfig.Styles))
			}
			if fmt.Sprint(actualMarkdownConfig.Scripts) != fmt.Sprint(test.expectedMarkdownConfig[j].Scripts) {
				t.Errorf("Test %d expected %dth Markdown Config Scripts to be  %s  , but got %s",
					i, j, fmt.Sprint(test.expectedMarkdownConfig[j].Scripts), fmt.Sprint(actualMarkdownConfig.Scripts))
			}

		}
	}

}
