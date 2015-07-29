package setup

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/mholt/caddy/middleware"
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
	if fmt.Sprint(myHandler.Configs[0].Extensions) != fmt.Sprint([]string{".md"}) {
		t.Errorf("Expected .md  as the Default Extension")
	}
}

func TestMarkdownStaticGen(t *testing.T) {
	c := NewTestController(`markdown /blog {
	ext .md
	template tpl_with_include.html
	sitegen
}`)

	c.Root = "./testdata"
	mid, err := Markdown(c)

	if err != nil {
		t.Errorf("Expected no errors, got: %v", err)
	}

	if mid == nil {
		t.Fatal("Expected middleware, was nil instead")
	}

	for _, start := range c.Startup {
		err := start()
		if err != nil {
			t.Errorf("Startup error: %v", err)
		}
	}

	next := middleware.HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) {
		t.Fatalf("Next shouldn't be called")
		return 0, nil
	})
	hndlr := mid(next)
	mkdwn, ok := hndlr.(markdown.Markdown)
	if !ok {
		t.Fatalf("Was expecting a markdown.Markdown but got %T", hndlr)
	}

	expectedStaticFiles := map[string]string{"/blog/first_post.md": "testdata/generated_site/blog/first_post.md/index.html"}
	if fmt.Sprint(expectedStaticFiles) != fmt.Sprint(mkdwn.Configs[0].StaticFiles) {
		t.Fatalf("Test expected StaticFiles to be  %s, but got %s",
			fmt.Sprint(expectedStaticFiles), fmt.Sprint(mkdwn.Configs[0].StaticFiles))
	}

	filePath := "testdata/generated_site/blog/first_post.md/index.html"
	if _, err := os.Stat(filePath); err != nil {
		t.Fatalf("An error occured when getting the file information: %v", err)
	}

	html, err := ioutil.ReadFile(filePath)
	if err != nil {
		t.Fatalf("An error occured when getting the file content: %v", err)
	}

	expectedBody := `<!DOCTYPE html>
<html>
<head>
<title>first_post</title>
</head>
<body>
<h1>Header title</h1>

<h1>Test h1</h1>

</body>
</html>
`
	if string(html) != expectedBody {
		t.Fatalf("Expected file content: %v got: %v", expectedBody, html)
	}

	fp := filepath.Join(c.Root, markdown.DefaultStaticDir)
	if err = os.RemoveAll(fp); err != nil {
		t.Errorf("Error while removing the generated static files: ", err)
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
		{`markdown /blog {
	ext .md
	template tpl_with_include.html
	sitegen
}`, false, []markdown.Config{{
			PathScope:  "/blog",
			Extensions: []string{".md"},
			Templates:  map[string]string{markdown.DefaultTemplate: "testdata/tpl_with_include.html"},
			StaticDir:  markdown.DefaultStaticDir,
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
