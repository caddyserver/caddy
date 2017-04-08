package markdown

import (
	"bufio"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"text/template"
	"time"

	"github.com/mholt/caddy/caddyhttp/httpserver"
	"github.com/russross/blackfriday"
)

func TestMarkdown(t *testing.T) {
	rootDir := "./testdata"

	f := func(filename string) string {
		return filepath.ToSlash(rootDir + string(filepath.Separator) + filename)
	}

	md := Markdown{
		Root:    rootDir,
		FileSys: http.Dir(rootDir),
		Configs: []*Config{
			{
				Renderer:  blackfriday.HtmlRenderer(0, "", ""),
				PathScope: "/blog",
				Extensions: map[string]struct{}{
					".md": {},
				},
				IndexFiles: []string{"index.md"},
				Styles:     []string{},
				Scripts:    []string{},
				Template:   setDefaultTemplate(f("markdown_tpl.html")),
			},
			{
				Renderer:  blackfriday.HtmlRenderer(0, "", ""),
				PathScope: "/docflags",
				Extensions: map[string]struct{}{
					".md": {},
				},
				IndexFiles: []string{"index.md"},
				Styles:     []string{},
				Scripts:    []string{},
				Template:   setDefaultTemplate(f("docflags/template.txt")),
			},
			{
				Renderer:  blackfriday.HtmlRenderer(0, "", ""),
				PathScope: "/log",
				Extensions: map[string]struct{}{
					".md": {},
				},
				IndexFiles: []string{"index.md"},
				Styles:     []string{"/resources/css/log.css", "/resources/css/default.css"},
				Scripts:    []string{"/resources/js/log.js", "/resources/js/default.js"},
				Template:   GetDefaultTemplate(),
			},
			{
				Renderer:  blackfriday.HtmlRenderer(0, "", ""),
				PathScope: "/og",
				Extensions: map[string]struct{}{
					".md": {},
				},
				IndexFiles: []string{"index.md"},
				Styles:     []string{},
				Scripts:    []string{},
				Template:   setDefaultTemplate(f("markdown_tpl.html")),
			},
		},

		Next: httpserver.HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) {
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
<title>Markdown test 1</title>
</head>
<body>
<h1>Header for: Markdown test 1</h1>

Welcome to A Caddy website!
<h2>Welcome on the blog</h2>

<p>Body</p>

<pre><code class="language-go">func getTrue() bool {
    return true
}
</code></pre>

</body>
</html>
`
	if !equalStrings(respBody, expectedBody) {
		t.Fatalf("Expected body: %v got: %v", expectedBody, respBody)
	}

	req, err = http.NewRequest("GET", "/docflags/test.md", nil)
	if err != nil {
		t.Fatalf("Could not create HTTP request: %v", err)
	}
	rec = httptest.NewRecorder()

	md.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("Wrong status, expected: %d and got %d", http.StatusOK, rec.Code)
	}
	respBody = rec.Body.String()
	expectedBody = `Doc.var_string hello
Doc.var_bool <no value>
DocFlags.var_string <no value>
DocFlags.var_bool true`

	if !equalStrings(respBody, expectedBody) {
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
		<title>Markdown test 2</title>
		<meta charset="utf-8">
		<link rel="stylesheet" href="/resources/css/log.css">
		<link rel="stylesheet" href="/resources/css/default.css">
		<script src="/resources/js/log.js"></script>
		<script src="/resources/js/default.js"></script>
	</head>
	<body>
		<h2>Welcome on the blog</h2>

<p>Body</p>

<pre><code class="language-go">func getTrue() bool {
    return true
}
</code></pre>

	</body>
</html>`

	if !equalStrings(respBody, expectedBody) {
		t.Fatalf("Expected body: %v got: %v", expectedBody, respBody)
	}

	req, err = http.NewRequest("GET", "/og/first.md", nil)
	if err != nil {
		t.Fatalf("Could not create HTTP request: %v", err)
	}
	rec = httptest.NewRecorder()
	currenttime := time.Now().Local().Add(-time.Second)
	_ = os.Chtimes("testdata/og/first.md", currenttime, currenttime)
	currenttime = time.Now().Local()
	_ = os.Chtimes("testdata/og_static/og/first.md/index.html", currenttime, currenttime)
	time.Sleep(time.Millisecond * 200)

	md.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("Wrong status, expected: %d and got %d", http.StatusOK, rec.Code)
	}
	respBody = rec.Body.String()
	expectedBody = `<!DOCTYPE html>
<html>
<head>
<title>first_post</title>
</head>
<body>
<h1>Header for: first_post</h1>

Welcome to title!
<h1>Test h1</h1>

</body>
</html>`

	if !equalStrings(respBody, expectedBody) {
		t.Fatalf("Expected body: %v got: %v", expectedBody, respBody)
	}
}

func equalStrings(s1, s2 string) bool {
	s1 = strings.TrimSpace(s1)
	s2 = strings.TrimSpace(s2)
	in := bufio.NewScanner(strings.NewReader(s1))
	for in.Scan() {
		txt := strings.TrimSpace(in.Text())
		if !strings.HasPrefix(strings.TrimSpace(s2), txt) {
			return false
		}
		s2 = strings.Replace(s2, txt, "", 1)
	}
	return true
}

func setDefaultTemplate(filename string) *template.Template {
	buf, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil
	}

	return template.Must(GetDefaultTemplate().Parse(string(buf)))
}
