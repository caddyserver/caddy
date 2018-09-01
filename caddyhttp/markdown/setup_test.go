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
	"bytes"
	"fmt"
	"net/http"
	"reflect"
	"testing"
	"text/template"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func TestSetup(t *testing.T) {
	c := caddy.NewTestController("http", `markdown /blog`)
	err := setup(c)
	if err != nil {
		t.Errorf("Expected no errors, got: %v", err)
	}
	mids := httpserver.GetConfig(c).Middleware()
	if len(mids) == 0 {
		t.Fatal("Expected middleware, got 0 instead")
	}

	handler := mids[0](httpserver.EmptyNext)
	myHandler, ok := handler.(Markdown)

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
		expectedMarkdownConfig []Config
	}{

		{`markdown /blog {
	ext .md .txt
	css /resources/css/blog.css
	js  /resources/js/blog.js
}`, false, []Config{{
			PathScope: "/blog",
			Extensions: map[string]struct{}{
				".md":  {},
				".txt": {},
			},
			Styles:        []string{"/resources/css/blog.css"},
			Scripts:       []string{"/resources/js/blog.js"},
			Template:      GetDefaultTemplate(),
			TemplateFiles: make(map[string]*cachedFileInfo),
		}}},
		{`markdown /blog {
	ext .md
	template tpl_with_include.html
}`, false, []Config{{
			PathScope: "/blog",
			Extensions: map[string]struct{}{
				".md": {},
			},
			Template: setDefaultTemplate("./testdata/tpl_with_include.html"),
			TemplateFiles: map[string]*cachedFileInfo{
				"": {path: "testdata/tpl_with_include.html"},
			},
		}}},
	}

	for i, test := range tests {
		c := caddy.NewTestController("http", test.inputMarkdownConfig)
		httpserver.GetConfig(c).Root = "./testdata"
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
			if ok, tx, ty := equalTemplates(actualMarkdownConfig.Template, test.expectedMarkdownConfig[j].Template); !ok {
				t.Errorf("Test %d the %dth Markdown Config Templates did not match, expected %s to be %s", i, j, tx, ty)
			}
			if expect, got := test.expectedMarkdownConfig[j].TemplateFiles, actualMarkdownConfig.TemplateFiles; !reflect.DeepEqual(expect, got) {
				t.Errorf("Test %d the %d Markdown config TemplateFiles did not match, expect %v, but got %v", i, j, expect, got)
			}

		}
	}
}

func equalTemplates(i, j *template.Template) (bool, string, string) {
	// Just in case :)
	if i == j {
		return true, "", ""
	}

	// We can't do much here, templates can't really be compared.  However,
	// we can execute the templates and compare their outputs to be reasonably
	// sure that they're the same.

	// This is exceedingly ugly.
	ctx := httpserver.Context{
		Root: http.Dir("./testdata"),
	}

	md := Data{
		Context: ctx,
		Doc:     make(map[string]interface{}),
		Styles:  []string{"style1"},
		Scripts: []string{"js1"},
	}
	md.Doc["title"] = "some title"
	md.Doc["body"] = "some body"

	bufi := new(bytes.Buffer)
	bufj := new(bytes.Buffer)

	if err := i.Execute(bufi, md); err != nil {
		return false, fmt.Sprintf("%v", err), ""
	}
	if err := j.Execute(bufj, md); err != nil {
		return false, "", fmt.Sprintf("%v", err)
	}

	return bytes.Equal(bufi.Bytes(), bufj.Bytes()), string(bufi.Bytes()), string(bufj.Bytes())
}
