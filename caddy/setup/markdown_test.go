package setup

import (
	"fmt"
	"testing"

	"github.com/mholt/caddy/middleware/markdown"
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
	if len(myHandler.Configs[0].Extensions) != 3 {
		t.Error("Expected 3 markdown extensions")
	}
	for _, key := range []string{".md", ".markdown", ".mdown"} {
		if ext, ok := myHandler.Configs[0].Extensions[key]; !ok {
			t.Errorf("Expected extensions to contain %v", ext)
		}
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
			PathScope: "/blog",
			Extensions: map[string]struct{}{
				".md":  struct{}{},
				".txt": struct{}{},
			},
			Styles:  []string{"/resources/css/blog.css"},
			Scripts: []string{"/resources/js/blog.js"},
		}}},
		{`markdown /blog {
	ext .md
	template tpl_with_include.html
}`, false, []markdown.Config{{
			PathScope: "/blog",
			Extensions: map[string]struct{}{
				".md": struct{}{},
			},
			Templates: map[string]string{markdown.DefaultTemplate: "testdata/tpl_with_include.html"},
		}}},
	}
	for i, test := range tests {
		c := NewTestController(test.inputMarkdownConfig)
		c.Root = "./testdata"
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
			if fmt.Sprint(actualMarkdownConfig.Templates) != fmt.Sprint(test.expectedMarkdownConfig[j].Templates) {
				t.Errorf("Test %d expected %dth Markdown Config Templates to be  %s  , but got %s",
					i, j, fmt.Sprint(test.expectedMarkdownConfig[j].Templates), fmt.Sprint(actualMarkdownConfig.Templates))
			}
		}
	}

}
