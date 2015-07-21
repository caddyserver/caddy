package markdown

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/russross/blackfriday"
)

func TestMarkdown(t *testing.T) {
	templates := make(map[string]string)
	templates[DefaultTemplate] = "markdown_tpl.html"
	md := Markdown{
		Root:    "/blog",
		FileSys: http.Dir("."),
		Configs: []Config{
			Config{
				Renderer:   blackfriday.HtmlRenderer(0, "", ""),
				PathScope:  "/blog",
				Extensions: []string{"md"},
				Styles:     []string{},
				Scripts:    []string{},
				Templates:  templates,
			},
		},
		IndexFiles: []string{"index.html"},
	}

	req, err := http.NewRequest("GET", "/blog/test.md", nil)
	if err != nil {
		t.Fatalf("Could not create HTTP request: %v", err)
	}

	rec := httptest.NewRecorder()

	md.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("Wrong status, expected: %d and got %d", http.StatusOK, rec.Code)
	}

	respBody := rec.Body.String()
	expectedBody := `<!DOCTYPE html>
<html>
<head>
<title>Markdown test</title>
</head>
<body>
<h1>Header</h1>

Welcome to A Caddy website!
<h2>Welcome on the blog</h2>

<p>Body</p>

<p><code>go
func getTrue() bool {
    return true
}
</code></p>

</body>
</html>
`

	if respBody != expectedBody {
		t.Fatalf("Expected body: %v got: %v", expectedBody, respBody)
	}
}
