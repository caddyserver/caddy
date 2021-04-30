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
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestMarkdown(t *testing.T) {
	context := getContextOrFail(t)

	for i, test := range []struct {
		body   string
		expect string
	}{
		{
			body:   "- str1\n- str2\n",
			expect: "<ul>\n<li>str1</li>\n<li>str2</li>\n</ul>\n",
		},
	} {
		result, err := context.funcMarkdown(test.body)
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
		context := getContextOrFail(t)
		context.Req.AddCookie(test.cookie)
		actual := context.Cookie(test.cookieName)
		if actual != test.expect {
			t.Errorf("Test %d: Expected cookie value '%s' but got '%s' for cookie with name '%s'",
				i, test.expect, actual, test.cookieName)
		}
	}
}

func TestCookieMultipleCookies(t *testing.T) {
	context := getContextOrFail(t)

	cookieNameBase, cookieValueBase := "cookieName", "cookieValue"

	for i := 0; i < 10; i++ {
		context.Req.AddCookie(&http.Cookie{
			Name:  fmt.Sprintf("%s%d", cookieNameBase, i),
			Value: fmt.Sprintf("%s%d", cookieValueBase, i),
		})
	}

	for i := 0; i < 10; i++ {
		expectedCookieVal := fmt.Sprintf("%s%d", cookieValueBase, i)
		actualCookieVal := context.Cookie(fmt.Sprintf("%s%d", cookieNameBase, i))
		if actualCookieVal != expectedCookieVal {
			t.Errorf("Expected cookie value %s, found %s", expectedCookieVal, actualCookieVal)
		}
	}
}

func TestIP(t *testing.T) {
	context := getContextOrFail(t)
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
		context.Req.RemoteAddr = test.inputRemoteAddr
		if actual := context.RemoteIP(); actual != test.expect {
			t.Errorf("Test %d: Expected %s but got %s", i, test.expect, actual)
		}
	}
}

func TestStripHTML(t *testing.T) {
	context := getContextOrFail(t)

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
		actual := context.funcStripHTML(test.input)
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
			verifyErr: os.IsNotExist,
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
			verifyErr: os.IsNotExist,
		},
	} {
		context := getContextOrFail(t)
		var dirPath string
		var err error

		// create files for test case
		if test.fileNames != nil {
			dirPath, err = ioutil.TempDir(fmt.Sprintf("%s", context.Root), "caddy_ctxtest")
			if err != nil {
				t.Fatalf("Test %d: Expected no error creating directory, got: '%s'", i, err.Error())
			}
			for _, name := range test.fileNames {
				absFilePath := filepath.Join(dirPath, name)
				if err = ioutil.WriteFile(absFilePath, []byte(""), os.ModePerm); err != nil {
					os.RemoveAll(dirPath)
					t.Fatalf("Test %d: Expected no error creating file, got: '%s'", i, err.Error())
				}
			}
		}

		// perform test
		input := filepath.ToSlash(filepath.Join(filepath.Base(dirPath), test.inputBase))
		actual, err := context.funcListFiles(input)
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
			if err := os.RemoveAll(dirPath); err != nil && !os.IsNotExist(err) {
				t.Fatalf("Test %d: Expected no error removing temporary test directory, got: %v", i, err)
			}
		}
	}
}

func TestSplitFrontMatter(t *testing.T) {
	context := getContextOrFail(t)

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
		result, _ := context.funcSplitFrontMatter(test.input)
		if result.Meta["title"] != test.expect {
			t.Errorf("Test %d: Expected %s, found %s. Input was SplitFrontMatter(%s)", i, test.expect, result.Meta["title"], test.input)
		}
		if result.Body != test.body {
			t.Errorf("Test %d: Expected body %s, found %s. Input was SplitFrontMatter(%s)", i, test.body, result.Body, test.input)
		}
	}

}

func getContextOrFail(t *testing.T) TemplateContext {
	context, err := initTestContext()
	if err != nil {
		t.Fatalf("failed to prepare test context: %v", err)
	}
	return context
}

func initTestContext() (TemplateContext, error) {
	body := bytes.NewBufferString("request body")
	request, err := http.NewRequest("GET", "https://example.com/foo/bar", body)
	if err != nil {
		return TemplateContext{}, err
	}
	return TemplateContext{
		Root:       http.Dir(os.TempDir()),
		Req:        request,
		RespHeader: WrappedHeader{make(http.Header)},
	}, nil
}
