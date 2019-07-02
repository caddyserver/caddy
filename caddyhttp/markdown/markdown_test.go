// Copyright 2015 Light Code Labs, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package markdown

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"text/template"

	"github.com/caddyserver/caddy"
	"github.com/caddyserver/caddy/caddyhttp/httpserver"
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

	get := func(url string) string {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			t.Fatalf("Could not create HTTP request: %v", err)
		}
		rec := httptest.NewRecorder()
		code, err := md.ServeHTTP(rec, req)
		if err != nil {
			t.Fatal(err)
		}
		if code != http.StatusOK {
			t.Fatalf("Wrong status, expected: %d and got %d", http.StatusOK, code)
		}
		return rec.Body.String()
	}

	respBody := get("/blog/test.md")
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
	if respBody != expectedBody {
		t.Fatalf("Expected body:\n%q\ngot:\n%q", expectedBody, respBody)
	}

	respBody = get("/docflags/test.md")
	expectedBody = `Doc.var_string hello
Doc.var_bool true
`

	if respBody != expectedBody {
		t.Fatalf("Expected body:\n%q\ngot:\n%q", expectedBody, respBody)
	}

	respBody = get("/log/test.md")
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

	if respBody != expectedBody {
		t.Fatalf("Expected body:\n%q\ngot:\n%q", expectedBody, respBody)
	}

	respBody = get("/og/first.md")
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
</html>
`

	if respBody != expectedBody {
		t.Fatalf("Expected body:\n%q\ngot:\n%q", expectedBody, respBody)
	}
}

func setDefaultTemplate(filename string) *template.Template {
	buf, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil
	}

	return template.Must(GetDefaultTemplate().Parse(string(buf)))
}

func TestTemplateReload(t *testing.T) {
	const (
		templateFile = "testdata/test.html"
		targetFile   = "testdata/hello.md"
	)
	c := caddy.NewTestController("http", `markdown {
		template `+templateFile+`
	}`)

	err := ioutil.WriteFile(templateFile, []byte("hello {{.Doc.body}}"), 0644)
	if err != nil {
		t.Fatal(err)
	}
	err = ioutil.WriteFile(targetFile, []byte("caddy"), 0644)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		os.Remove(templateFile)
		os.Remove(targetFile)
	}()

	config, err := markdownParse(c)
	if err != nil {
		t.Fatal(err)
	}
	md := Markdown{
		Root:    "./testdata",
		FileSys: http.Dir("./testdata"),
		Configs: config,
		Next: httpserver.HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) {
			t.Fatalf("Next shouldn't be called")
			return 0, nil
		}),
	}

	req := httptest.NewRequest("GET", "/hello.md", nil)
	get := func() string {
		rec := httptest.NewRecorder()
		code, err := md.ServeHTTP(rec, req)
		if err != nil {
			t.Fatal(err)
		}
		if code != http.StatusOK {
			t.Fatalf("Wrong status, expected: %d and got %d", http.StatusOK, code)
		}
		return rec.Body.String()
	}

	if expect, got := "hello <p>caddy</p>\n", get(); expect != got {
		t.Fatalf("Expected body:\n%q\nbut got:\n%q", expect, got)
	}

	// update template
	err = ioutil.WriteFile(templateFile, []byte("hi {{.Doc.body}}"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	if expect, got := "hi <p>caddy</p>\n", get(); expect != got {
		t.Fatalf("Expected body:\n%q\nbut got:\n%q", expect, got)
	}

}
