package markdown

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mholt/caddy/middleware"
	"github.com/russross/blackfriday"
)

func TestMarkdown(t *testing.T) {
	templates := make(map[string]string)
	templates[DefaultTemplate] = "testdata/markdown_tpl.html"
	md := Markdown{
		Root:    "./testdata",
		FileSys: http.Dir("./testdata"),
		Configs: []Config{
			Config{
				Renderer:   blackfriday.HtmlRenderer(0, "", ""),
				PathScope:  "/blog",
				Extensions: []string{".md"},
				Styles:     []string{},
				Scripts:    []string{},
				Templates:  templates,
			},
			Config{
				Renderer:   blackfriday.HtmlRenderer(0, "", ""),
				PathScope:  "/log",
				Extensions: []string{".md"},
				Styles:     []string{"/resources/css/log.css", "/resources/css/default.css"},
				Scripts:    []string{"/resources/js/log.js", "/resources/js/default.js"},
				Templates:  make(map[string]string),
			},
		},
		IndexFiles: []string{"index.html"},
		Next: middleware.HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) {
			t.Fatalf("Next shouldn't be called")
			return 0, nil
		}),
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

	req, err = http.NewRequest("GET", "/log/test.md", nil)
	if err != nil {
		t.Fatalf("Could not create HTTP request: %v", err)
	}
	rec = httptest.NewRecorder()

	md.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("Wrong status, expected: %d and got %d", http.StatusOK, rec.Code)
	}
	respBody = rec.Body.String()
	expectedBody = `<!DOCTYPE html>
<html>
	<head>
		<title>Markdown test</title>
		<meta charset="utf-8">
		<link rel="stylesheet" href="/resources/css/log.css">
<link rel="stylesheet" href="/resources/css/default.css">

		<script src="/resources/js/log.js"></script>
<script src="/resources/js/default.js"></script>

	</head>
	<body>
		<h2>Welcome on the blog</h2>

<p>Body</p>

<p><code>go
func getTrue() bool {
    return true
}
</code></p>

	</body>
</html>`

	replacer := strings.NewReplacer("\r", "", "\n", "")
	respBody = replacer.Replace(respBody)
	expectedBody = replacer.Replace(expectedBody)
	if respBody != expectedBody {
		t.Fatalf("Expected body: %v got: %v", expectedBody, respBody)
	}
}
