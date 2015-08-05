package markdown

import (
	"bufio"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

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
				Renderer:    blackfriday.HtmlRenderer(0, "", ""),
				PathScope:   "/blog",
				Extensions:  []string{".md"},
				Styles:      []string{},
				Scripts:     []string{},
				Templates:   templates,
				StaticDir:   DefaultStaticDir,
				StaticFiles: make(map[string]string),
			},
			Config{
				Renderer:    blackfriday.HtmlRenderer(0, "", ""),
				PathScope:   "/log",
				Extensions:  []string{".md"},
				Styles:      []string{"/resources/css/log.css", "/resources/css/default.css"},
				Scripts:     []string{"/resources/js/log.js", "/resources/js/default.js"},
				Templates:   make(map[string]string),
				StaticDir:   DefaultStaticDir,
				StaticFiles: make(map[string]string),
			},
			Config{
				Renderer:    blackfriday.HtmlRenderer(0, "", ""),
				PathScope:   "/og",
				Extensions:  []string{".md"},
				Styles:      []string{},
				Scripts:     []string{},
				Templates:   templates,
				StaticDir:   "testdata/og_static",
				StaticFiles: map[string]string{"/og/first.md": "testdata/og_static/og/first.md/index.html"},
				Links: []PageLink{
					PageLink{
						Title:   "first",
						Summary: "",
						Date:    time.Now(),
						URL:     "/og/first.md",
					},
				},
			},
		},
		IndexFiles: []string{"index.html"},
		Next: middleware.HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) {
			t.Fatalf("Next shouldn't be called")
			return 0, nil
		}),
	}

	for i := range md.Configs {
		c := &md.Configs[i]
		if err := GenerateStatic(md, c); err != nil {
			t.Fatalf("Error: %v", err)
		}
		Watch(md, c, time.Millisecond*100)
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

	if !equalStrings(respBody, expectedBody) {
		t.Fatalf("Expected body: %v got: %v", expectedBody, respBody)
	}

	req, err = http.NewRequest("GET", "/og/first.md", nil)
	if err != nil {
		t.Fatalf("Could not create HTTP request: %v", err)
	}
	rec = httptest.NewRecorder()
	currenttime := time.Now().Local().Add(-time.Second)
	err = os.Chtimes("testdata/og/first.md", currenttime, currenttime)
	currenttime = time.Now().Local()
	err = os.Chtimes("testdata/og_static/og/first.md/index.html", currenttime, currenttime)
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
<h1>Header</h1>

Welcome to title!
<h1>Test h1</h1>

</body>
</html>`

	if !equalStrings(respBody, expectedBody) {
		t.Fatalf("Expected body: %v got: %v", expectedBody, respBody)
	}

	expectedLinks := []string{
		"/blog/test.md",
		"/log/test.md",
	}

	for i, c := range md.Configs[:2] {
		log.Printf("Test number: %d, configuration links: %v, config: %v", i, c.Links, c)
		if c.Links[0].URL != expectedLinks[i] {
			t.Fatalf("Expected %v got %v", expectedLinks[i], c.Links[0].URL)
		}
	}

	// attempt to trigger race conditions
	var w sync.WaitGroup
	f := func() {
		req, err := http.NewRequest("GET", "/log/test.md", nil)
		if err != nil {
			t.Fatalf("Could not create HTTP request: %v", err)
		}
		rec := httptest.NewRecorder()

		md.ServeHTTP(rec, req)
		w.Done()
	}
	for i := 0; i < 5; i++ {
		w.Add(1)
		go f()
	}
	w.Wait()

	f = func() {
		GenerateStatic(md, &md.Configs[0])
		w.Done()
	}
	for i := 0; i < 5; i++ {
		w.Add(1)
		go f()
	}
	w.Wait()

	if err = os.RemoveAll(DefaultStaticDir); err != nil {
		t.Errorf("Error while removing the generated static files: %v", err)
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
