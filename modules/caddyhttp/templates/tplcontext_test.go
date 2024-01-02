// Copyright 2015 Matthew Holt and The Caddy Authors
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

package templates

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

type handle struct{}

func (h *handle) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Accept-Encoding") == "identity" {
		w.Write([]byte("good contents"))
	} else {
		w.Write([]byte("bad cause Accept-Encoding: " + r.Header.Get("Accept-Encoding")))
	}
}

func TestHTTPInclude(t *testing.T) {
	tplContext := getContextOrFail(t)
	for i, test := range []struct {
		uri     string
		handler *handle
		expect  string
	}{
		{
			uri:     "https://example.com/foo/bar",
			handler: &handle{},
			expect:  "good contents",
		},
	} {
		ctx := context.WithValue(tplContext.Req.Context(), caddyhttp.ServerCtxKey, test.handler)
		tplContext.Req = tplContext.Req.WithContext(ctx)
		tplContext.Req.Header.Add("Accept-Encoding", "gzip")
		result, err := tplContext.funcHTTPInclude(test.uri)
		if result != test.expect {
			t.Errorf("Test %d: expected '%s' but got '%s'", i, test.expect, result)
		}
		if err != nil {
			t.Errorf("Test %d: got error: %v", i, result)
		}
	}
}

func TestMarkdown(t *testing.T) {
	tplContext := getContextOrFail(t)

	for i, test := range []struct {
		body   string
		expect string
	}{
		{
			body:   "- str1\n- str2\n",
			expect: "<ul>\n<li>str1</li>\n<li>str2</li>\n</ul>\n",
		},
	} {
		result, err := tplContext.funcMarkdown(test.body)
		if result != test.expect {
			t.Errorf("Test %d: expected '%s' but got '%s'", i, test.expect, result)
		}
		if err != nil {
			t.Errorf("Test %d: got error: %v", i, result)
		}
	}
}

func TestCookie(t *testing.T) {
	for i, test := range []struct {
		cookie     *http.Cookie
		cookieName string
		expect     string
	}{
		{
			// happy path
			cookie:     &http.Cookie{Name: "cookieName", Value: "cookieValue"},
			cookieName: "cookieName",
			expect:     "cookieValue",
		},
		{
			// try to get a non-existing cookie
			cookie:     &http.Cookie{Name: "cookieName", Value: "cookieValue"},
			cookieName: "notExisting",
			expect:     "",
		},
		{
			// partial name match
			cookie:     &http.Cookie{Name: "cookie", Value: "cookieValue"},
			cookieName: "cook",
			expect:     "",
		},
		{
			// cookie with optional fields
			cookie:     &http.Cookie{Name: "cookie", Value: "cookieValue", Path: "/path", Domain: "https://localhost", Expires: time.Now().Add(10 * time.Minute), MaxAge: 120},
			cookieName: "cookie",
			expect:     "cookieValue",
		},
	} {
		tplContext := getContextOrFail(t)
		tplContext.Req.AddCookie(test.cookie)
		actual := tplContext.Cookie(test.cookieName)
		if actual != test.expect {
			t.Errorf("Test %d: Expected cookie value '%s' but got '%s' for cookie with name '%s'",
				i, test.expect, actual, test.cookieName)
		}
	}
}

func TestImport(t *testing.T) {
	for i, test := range []struct {
		fileContent string
		fileName    string
		shouldErr   bool
		expect      string
	}{
		{
			// file exists, template is defined
			fileContent: `{{ define "imported" }}text{{end}}`,
			fileName:    "file1",
			shouldErr:   false,
			expect:      `"imported"`,
		},
		{
			// file does not exit
			fileContent: "",
			fileName:    "",
			shouldErr:   true,
		},
	} {
		tplContext := getContextOrFail(t)
		var absFilePath string

		// create files for test case
		if test.fileName != "" {
			absFilePath := filepath.Join(fmt.Sprintf("%s", tplContext.Root), test.fileName)
			if err := os.WriteFile(absFilePath, []byte(test.fileContent), os.ModePerm); err != nil {
				os.Remove(absFilePath)
				t.Fatalf("Test %d: Expected no error creating file, got: '%s'", i, err.Error())
			}
		}

		// perform test
		tplContext.NewTemplate("parent")
		actual, err := tplContext.funcImport(test.fileName)
		templateWasDefined := strings.Contains(tplContext.tpl.DefinedTemplates(), test.expect)
		if err != nil {
			if !test.shouldErr {
				t.Errorf("Test %d: Expected no error, got: '%s'", i, err)
			}
		} else if test.shouldErr {
			t.Errorf("Test %d: Expected error but had none", i)
		} else if !templateWasDefined && actual != "" {
			// template should be defined, return value should be an empty string
			t.Errorf("Test %d: Expected template %s to be define but got %s", i, test.expect, tplContext.tpl.DefinedTemplates())
		}

		if absFilePath != "" {
			if err := os.Remove(absFilePath); err != nil && !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("Test %d: Expected no error removing temporary test file, got: %v", i, err)
			}
		}
	}
}

func TestNestedInclude(t *testing.T) {
	for i, test := range []struct {
		child      string
		childFile  string
		parent     string
		parentFile string
		shouldErr  bool
		expect     string
		child2     string
		child2File string
	}{
		{
			// include in parent
			child:      `{{ include "file1" }}`,
			childFile:  "file0",
			parent:     `{{ $content := "file2" }}{{ $p := include $content}}`,
			parentFile: "file1",
			shouldErr:  false,
			expect:     ``,
			child2:     `This shouldn't show`,
			child2File: "file2",
		},
	} {
		context := getContextOrFail(t)
		var absFilePath string
		var absFilePath0 string
		var absFilePath1 string
		var buf *bytes.Buffer
		var err error

		// create files and for test case
		if test.parentFile != "" {
			absFilePath = filepath.Join(fmt.Sprintf("%s", context.Root), test.parentFile)
			if err := os.WriteFile(absFilePath, []byte(test.parent), os.ModePerm); err != nil {
				os.Remove(absFilePath)
				t.Fatalf("Test %d: Expected no error creating file, got: '%s'", i, err.Error())
			}
		}
		if test.childFile != "" {
			absFilePath0 = filepath.Join(fmt.Sprintf("%s", context.Root), test.childFile)
			if err := os.WriteFile(absFilePath0, []byte(test.child), os.ModePerm); err != nil {
				os.Remove(absFilePath0)
				t.Fatalf("Test %d: Expected no error creating file, got: '%s'", i, err.Error())
			}
		}
		if test.child2File != "" {
			absFilePath1 = filepath.Join(fmt.Sprintf("%s", context.Root), test.child2File)
			if err := os.WriteFile(absFilePath1, []byte(test.child2), os.ModePerm); err != nil {
				os.Remove(absFilePath0)
				t.Fatalf("Test %d: Expected no error creating file, got: '%s'", i, err.Error())
			}
		}

		buf = bufPool.Get().(*bytes.Buffer)
		buf.Reset()
		defer bufPool.Put(buf)
		buf.WriteString(test.child)
		err = context.executeTemplateInBuffer(test.childFile, buf)

		if err != nil {
			if !test.shouldErr {
				t.Errorf("Test %d: Expected no error, got: '%s'", i, err)
			}
		} else if test.shouldErr {
			t.Errorf("Test %d: Expected error but had none", i)
		} else if buf.String() != test.expect {
			//
			t.Errorf("Test %d: Expected '%s' but got '%s'", i, test.expect, buf.String())
		}

		if absFilePath != "" {
			if err := os.Remove(absFilePath); err != nil && !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("Test %d: Expected no error removing temporary test file, got: %v", i, err)
			}
		}
		if absFilePath0 != "" {
			if err := os.Remove(absFilePath0); err != nil && !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("Test %d: Expected no error removing temporary test file, got: %v", i, err)
			}
		}
		if absFilePath1 != "" {
			if err := os.Remove(absFilePath1); err != nil && !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("Test %d: Expected no error removing temporary test file, got: %v", i, err)
			}
		}
	}
}

func TestInclude(t *testing.T) {
	for i, test := range []struct {
		fileContent string
		fileName    string
		shouldErr   bool
		expect      string
		args        string
	}{
		{
			// file exists, content is text only
			fileContent: "text",
			fileName:    "file1",
			shouldErr:   false,
			expect:      "text",
		},
		{
			// file exists, content is template
			fileContent: "{{ if . }}text{{ end }}",
			fileName:    "file1",
			shouldErr:   false,
			expect:      "text",
		},
		{
			// file does not exit
			fileContent: "",
			fileName:    "",
			shouldErr:   true,
		},
		{
			// args
			fileContent: "{{ index .Args 0 }}",
			fileName:    "file1",
			shouldErr:   false,
			args:        "text",
			expect:      "text",
		},
		{
			// args, reference arg out of range
			fileContent: "{{ index .Args 1 }}",
			fileName:    "file1",
			shouldErr:   true,
			args:        "text",
		},
	} {
		tplContext := getContextOrFail(t)
		var absFilePath string

		// create files for test case
		if test.fileName != "" {
			absFilePath := filepath.Join(fmt.Sprintf("%s", tplContext.Root), test.fileName)
			if err := os.WriteFile(absFilePath, []byte(test.fileContent), os.ModePerm); err != nil {
				os.Remove(absFilePath)
				t.Fatalf("Test %d: Expected no error creating file, got: '%s'", i, err.Error())
			}
		}

		// perform test
		actual, err := tplContext.funcInclude(test.fileName, test.args)
		if err != nil {
			if !test.shouldErr {
				t.Errorf("Test %d: Expected no error, got: '%s'", i, err)
			}
		} else if test.shouldErr {
			t.Errorf("Test %d: Expected error but had none", i)
		} else if actual != test.expect {
			t.Errorf("Test %d: Expected %s but got %s", i, test.expect, actual)
		}

		if absFilePath != "" {
			if err := os.Remove(absFilePath); err != nil && !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("Test %d: Expected no error removing temporary test file, got: %v", i, err)
			}
		}
	}
}

func TestCookieMultipleCookies(t *testing.T) {
	tplContext := getContextOrFail(t)

	cookieNameBase, cookieValueBase := "cookieName", "cookieValue"

	for i := 0; i < 10; i++ {
		tplContext.Req.AddCookie(&http.Cookie{
			Name:  fmt.Sprintf("%s%d", cookieNameBase, i),
			Value: fmt.Sprintf("%s%d", cookieValueBase, i),
		})
	}

	for i := 0; i < 10; i++ {
		expectedCookieVal := fmt.Sprintf("%s%d", cookieValueBase, i)
		actualCookieVal := tplContext.Cookie(fmt.Sprintf("%s%d", cookieNameBase, i))
		if actualCookieVal != expectedCookieVal {
			t.Errorf("Expected cookie value %s, found %s", expectedCookieVal, actualCookieVal)
		}
	}
}

func TestIP(t *testing.T) {
	tplContext := getContextOrFail(t)
	for i, test := range []struct {
		inputRemoteAddr string
		expect          string
	}{
		{"1.1.1.1:1111", "1.1.1.1"},
		{"1.1.1.1", "1.1.1.1"},
		{"[::1]:11", "::1"},
		{"[2001:db8:a0b:12f0::1]", "[2001:db8:a0b:12f0::1]"},
		{`[fe80:1::3%eth0]:44`, `fe80:1::3%eth0`},
	} {
		tplContext.Req.RemoteAddr = test.inputRemoteAddr
		if actual := tplContext.RemoteIP(); actual != test.expect {
			t.Errorf("Test %d: Expected %s but got %s", i, test.expect, actual)
		}
	}
}

func TestStripHTML(t *testing.T) {
	tplContext := getContextOrFail(t)

	for i, test := range []struct {
		input  string
		expect string
	}{
		{
			// no tags
			input:  `h1`,
			expect: `h1`,
		},
		{
			// happy path
			input:  `<h1>h1</h1>`,
			expect: `h1`,
		},
		{
			// tag in quotes
			input:  `<h1">">h1</h1>`,
			expect: `h1`,
		},
		{
			// multiple tags
			input:  `<h1><b>h1</b></h1>`,
			expect: `h1`,
		},
		{
			// tags not closed
			input:  `<h1`,
			expect: `<h1`,
		},
		{
			// false start
			input:  `<h1<b>hi`,
			expect: `<h1hi`,
		},
	} {
		actual := tplContext.funcStripHTML(test.input)
		if actual != test.expect {
			t.Errorf("Test %d: Expected %s, found %s. Input was StripHTML(%s)", i, test.expect, actual, test.input)
		}
	}
}

func TestFileListing(t *testing.T) {
	for i, test := range []struct {
		fileNames []string
		inputBase string
		shouldErr bool
		verifyErr func(error) bool
	}{
		{
			// directory and files exist
			fileNames: []string{"file1", "file2"},
			shouldErr: false,
		},
		{
			// directory exists, no files
			fileNames: []string{},
			shouldErr: false,
		},
		{
			// file or directory does not exist
			fileNames: nil,
			inputBase: "doesNotExist",
			shouldErr: true,
			verifyErr: func(err error) bool { return errors.Is(err, fs.ErrNotExist) },
		},
		{
			// directory and files exist, but path to a file
			fileNames: []string{"file1", "file2"},
			inputBase: "file1",
			shouldErr: true,
			verifyErr: func(err error) bool {
				return strings.HasSuffix(err.Error(), "is not a directory")
			},
		},
		{
			// try to escape Context Root
			fileNames: nil,
			inputBase: filepath.Join("..", "..", "..", "..", "..", "etc"),
			shouldErr: true,
			verifyErr: func(err error) bool { return errors.Is(err, fs.ErrNotExist) },
		},
	} {
		tplContext := getContextOrFail(t)
		var dirPath string
		var err error

		// create files for test case
		if test.fileNames != nil {
			dirPath, err = os.MkdirTemp(fmt.Sprintf("%s", tplContext.Root), "caddy_ctxtest")
			if err != nil {
				t.Fatalf("Test %d: Expected no error creating directory, got: '%s'", i, err.Error())
			}
			for _, name := range test.fileNames {
				absFilePath := filepath.Join(dirPath, name)
				if err = os.WriteFile(absFilePath, []byte(""), os.ModePerm); err != nil {
					os.RemoveAll(dirPath)
					t.Fatalf("Test %d: Expected no error creating file, got: '%s'", i, err.Error())
				}
			}
		}

		// perform test
		input := filepath.ToSlash(filepath.Join(filepath.Base(dirPath), test.inputBase))
		actual, err := tplContext.funcListFiles(input)
		if err != nil {
			if !test.shouldErr {
				t.Errorf("Test %d: Expected no error, got: '%s'", i, err)
			} else if !test.verifyErr(err) {
				t.Errorf("Test %d: Could not verify error content, got: '%s'", i, err)
			}
		} else if test.shouldErr {
			t.Errorf("Test %d: Expected error but had none", i)
		} else {
			numFiles := len(test.fileNames)
			// reflect.DeepEqual does not consider two empty slices to be equal
			if numFiles == 0 && len(actual) != 0 {
				t.Errorf("Test %d: Expected files %v, got: %v",
					i, test.fileNames, actual)
			} else {
				sort.Strings(actual)
				if numFiles > 0 && !reflect.DeepEqual(test.fileNames, actual) {
					t.Errorf("Test %d: Expected files %v, got: %v",
						i, test.fileNames, actual)
				}
			}
		}

		if dirPath != "" {
			if err := os.RemoveAll(dirPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("Test %d: Expected no error removing temporary test directory, got: %v", i, err)
			}
		}
	}
}

func TestSplitFrontMatter(t *testing.T) {
	tplContext := getContextOrFail(t)

	for i, test := range []struct {
		input  string
		expect string
		body   string
	}{
		{
			// yaml with windows newline
			input:  "---\r\ntitle: Welcome\r\n---\r\n# Test\\r\\n",
			expect: `Welcome`,
			body:   "\r\n# Test\\r\\n",
		},
		{
			// yaml
			input: `---
title: Welcome
---
### Test`,
			expect: `Welcome`,
			body:   "\n### Test",
		},
		{
			// yaml with dots for closer
			input: `---
title: Welcome
...
### Test`,
			expect: `Welcome`,
			body:   "\n### Test",
		},
		{
			// yaml with non-fence '...' line after closing fence (i.e. first matching closing fence should be used)
			input: `---
title: Welcome
---
### Test
...
yeah`,
			expect: `Welcome`,
			body:   "\n### Test\n...\nyeah",
		},
		{
			// toml
			input: `+++
title = "Welcome"
+++
### Test`,
			expect: `Welcome`,
			body:   "\n### Test",
		},
		{
			// json
			input: `{
    "title": "Welcome"
}
### Test`,
			expect: `Welcome`,
			body:   "\n### Test",
		},
	} {
		result, _ := tplContext.funcSplitFrontMatter(test.input)
		if result.Meta["title"] != test.expect {
			t.Errorf("Test %d: Expected %s, found %s. Input was SplitFrontMatter(%s)", i, test.expect, result.Meta["title"], test.input)
		}
		if result.Body != test.body {
			t.Errorf("Test %d: Expected body %s, found %s. Input was SplitFrontMatter(%s)", i, test.body, result.Body, test.input)
		}
	}
}

func TestHumanize(t *testing.T) {
	tplContext := getContextOrFail(t)
	for i, test := range []struct {
		format    string
		inputData string
		expect    string
		errorCase bool
		verifyErr func(actual_string, substring string) bool
	}{
		{
			format:    "size",
			inputData: "2048000",
			expect:    "2.0 MB",
			errorCase: false,
			verifyErr: strings.Contains,
		},
		{
			format:    "time",
			inputData: "Fri, 05 May 2022 15:04:05 +0200",
			expect:    "ago",
			errorCase: false,
			verifyErr: strings.HasSuffix,
		},
		{
			format:    "time:2006-Jan-02",
			inputData: "2022-May-05",
			expect:    "ago",
			errorCase: false,
			verifyErr: strings.HasSuffix,
		},
		{
			format:    "time",
			inputData: "Fri, 05 May 2022 15:04:05 GMT+0200",
			expect:    "error:",
			errorCase: true,
			verifyErr: strings.HasPrefix,
		},
	} {
		if actual, err := tplContext.funcHumanize(test.format, test.inputData); !test.verifyErr(actual, test.expect) {
			if !test.errorCase {
				t.Errorf("Test %d: Expected '%s' but got '%s'", i, test.expect, actual)
				if err != nil {
					t.Errorf("Test %d: error: %s", i, err.Error())
				}
			}
		}
	}
}

func getContextOrFail(t *testing.T) TemplateContext {
	tplContext, err := initTestContext()
	t.Cleanup(func() {
		os.RemoveAll(string(tplContext.Root.(http.Dir)))
	})
	if err != nil {
		t.Fatalf("failed to prepare test context: %v", err)
	}
	return tplContext
}

func initTestContext() (TemplateContext, error) {
	body := bytes.NewBufferString("request body")
	request, err := http.NewRequest("GET", "https://example.com/foo/bar", body)
	if err != nil {
		return TemplateContext{}, err
	}
	tmpDir, err := os.MkdirTemp(os.TempDir(), "caddy")
	if err != nil {
		return TemplateContext{}, err
	}
	return TemplateContext{
		Root:       http.Dir(tmpDir),
		Req:        request,
		RespHeader: WrappedHeader{make(http.Header)},
	}, nil
}
