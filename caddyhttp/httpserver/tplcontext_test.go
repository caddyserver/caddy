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

package httpserver

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"text/template"
)

func TestInclude(t *testing.T) {
	context := getContextOrFail(t)

	inputFilename := "test_file"
	absInFilePath := filepath.Join(fmt.Sprintf("%s", context.Root), inputFilename)
	defer func() {
		err := os.Remove(absInFilePath)
		if err != nil && !os.IsNotExist(err) {
			t.Fatalf("Failed to clean test file!")
		}
	}()

	tests := []struct {
		args                 []interface{}
		fileContent          string
		expectedContent      string
		shouldErr            bool
		expectedErrorContent string
	}{
		// Test 0 - all good
		{
			fileContent:          `str1 {{ .Root }} str2`,
			expectedContent:      fmt.Sprintf("str1 %s str2", context.Root),
			shouldErr:            false,
			expectedErrorContent: "",
		},
		// Test 1 - all good, with args
		{
			args:                 []interface{}{"hello", 5},
			fileContent:          `str1 {{ .Root }} str2 {{index .Args 0}} {{index .Args 1}}`,
			expectedContent:      fmt.Sprintf("str1 %s str2 %s %d", context.Root, "hello", 5),
			shouldErr:            false,
			expectedErrorContent: "",
		},
		// Test 2 - failure on template.Parse
		{
			fileContent:          `str1 {{ .Root } str2`,
			expectedContent:      "",
			shouldErr:            true,
			expectedErrorContent: `unexpected "}" in operand`,
		},
		// Test 3 - failure on template.Execute
		{
			fileContent:          `str1 {{ .InvalidField }} str2`,
			expectedContent:      "",
			shouldErr:            true,
			expectedErrorContent: `InvalidField`,
		},
		{
			fileContent:          `str1 {{ .InvalidField }} str2`,
			expectedContent:      "",
			shouldErr:            true,
			expectedErrorContent: `type httpserver.Context`,
		},
		// Test 4 - all good, with custom function
		{
			fileContent:          `hello {{ caddy }}`,
			expectedContent:      "hello caddy",
			shouldErr:            false,
			expectedErrorContent: "",
		},
	}

	TemplateFuncs["caddy"] = func() string { return "caddy" }
	for i, test := range tests {
		testPrefix := getTestPrefix(i)

		// WriteFile truncates the content
		err := ioutil.WriteFile(absInFilePath, []byte(test.fileContent), os.ModePerm)
		if err != nil {
			t.Fatal(testPrefix+"Failed to create test file. Error was: %v", err)
		}

		content, err := context.Include(inputFilename, test.args...)
		if err != nil {
			if !test.shouldErr {
				t.Errorf(testPrefix+"Expected no error, found [%s]", test.expectedErrorContent, err.Error())
			}
			if !strings.Contains(err.Error(), test.expectedErrorContent) {
				t.Errorf(testPrefix+"Expected error content [%s], found [%s]", test.expectedErrorContent, err.Error())
			}
		}

		if err == nil && test.shouldErr {
			t.Errorf(testPrefix+"Expected error [%s] but found nil. Input file was: %s", test.expectedErrorContent, inputFilename)
		}

		if content != test.expectedContent {
			t.Errorf(testPrefix+"Expected content [%s] but found [%s]. Input file was: %s", test.expectedContent, content, inputFilename)
		}
	}
}

func TestIncludeNotExisting(t *testing.T) {
	context := getContextOrFail(t)

	_, err := context.Include("not_existing")
	if err == nil {
		t.Errorf("Expected error but found nil!")
	}
}

func TestMarkdown(t *testing.T) {
	context := getContextOrFail(t)

	inputFilename := "test_file"
	absInFilePath := filepath.Join(fmt.Sprintf("%s", context.Root), inputFilename)
	defer func() {
		err := os.Remove(absInFilePath)
		if err != nil && !os.IsNotExist(err) {
			t.Fatalf("Failed to clean test file!")
		}
	}()

	tests := []struct {
		fileContent     string
		expectedContent string
	}{
		// Test 0 - test parsing of markdown
		{
			fileContent:     "* str1\n* str2\n",
			expectedContent: "<ul>\n<li>str1</li>\n<li>str2</li>\n</ul>\n",
		},
	}

	for i, test := range tests {
		testPrefix := getTestPrefix(i)

		// WriteFile truncates the content
		err := ioutil.WriteFile(absInFilePath, []byte(test.fileContent), os.ModePerm)
		if err != nil {
			t.Fatal(testPrefix+"Failed to create test file. Error was: %v", err)
		}

		content, _ := context.Markdown(inputFilename)
		if content != test.expectedContent {
			t.Errorf(testPrefix+"Expected content [%s] but found [%s]. Input file was: %s", test.expectedContent, content, inputFilename)
		}
	}
}

func TestCookie(t *testing.T) {

	tests := []struct {
		cookie        *http.Cookie
		cookieName    string
		expectedValue string
	}{
		// Test 0 - happy path
		{
			cookie:        &http.Cookie{Name: "cookieName", Value: "cookieValue"},
			cookieName:    "cookieName",
			expectedValue: "cookieValue",
		},
		// Test 1 - try to get a non-existing cookie
		{
			cookie:        &http.Cookie{Name: "cookieName", Value: "cookieValue"},
			cookieName:    "notExisting",
			expectedValue: "",
		},
		// Test 2 - partial name match
		{
			cookie:        &http.Cookie{Name: "cookie", Value: "cookieValue"},
			cookieName:    "cook",
			expectedValue: "",
		},
		// Test 3 - cookie with optional fields
		{
			cookie:        &http.Cookie{Name: "cookie", Value: "cookieValue", Path: "/path", Domain: "https://localhost", Expires: (time.Now().Add(10 * time.Minute)), MaxAge: 120},
			cookieName:    "cookie",
			expectedValue: "cookieValue",
		},
	}

	for i, test := range tests {
		testPrefix := getTestPrefix(i)

		// reinitialize the context for each test
		context := getContextOrFail(t)

		context.Req.AddCookie(test.cookie)

		actualCookieVal := context.Cookie(test.cookieName)

		if actualCookieVal != test.expectedValue {
			t.Errorf(testPrefix+"Expected cookie value [%s] but found [%s] for cookie with name %s", test.expectedValue, actualCookieVal, test.cookieName)
		}
	}
}

func TestCookieMultipleCookies(t *testing.T) {
	context := getContextOrFail(t)

	cookieNameBase, cookieValueBase := "cookieName", "cookieValue"

	// make sure that there's no state and multiple requests for different cookies return the correct result
	for i := 0; i < 10; i++ {
		context.Req.AddCookie(&http.Cookie{Name: fmt.Sprintf("%s%d", cookieNameBase, i), Value: fmt.Sprintf("%s%d", cookieValueBase, i)})
	}

	for i := 0; i < 10; i++ {
		expectedCookieVal := fmt.Sprintf("%s%d", cookieValueBase, i)
		actualCookieVal := context.Cookie(fmt.Sprintf("%s%d", cookieNameBase, i))
		if actualCookieVal != expectedCookieVal {
			t.Fatalf("Expected cookie value %s, found %s", expectedCookieVal, actualCookieVal)
		}
	}
}

func TestHeader(t *testing.T) {
	context := getContextOrFail(t)

	headerKey, headerVal := "Header1", "HeaderVal1"
	context.Req.Header.Add(headerKey, headerVal)

	actualHeaderVal := context.Header(headerKey)
	if actualHeaderVal != headerVal {
		t.Errorf("Expected header %s, found %s", headerVal, actualHeaderVal)
	}

	missingHeaderVal := context.Header("not-existing")
	if missingHeaderVal != "" {
		t.Errorf("Expected empty header value, found %s", missingHeaderVal)
	}
}

func TestHostname(t *testing.T) {
	context := getContextOrFail(t)

	tests := []struct {
		inputRemoteAddr  string
		expectedHostname string
	}{
		// TODO(mholt): Fix these tests, they're not portable. i.e. my resolver
		// returns "fwdr-8.fwdr-8.fwdr-8.fwdr-8." instead of these google ones.
		// Test 0 - ipv4 with port
		// {"8.8.8.8:1111", "google-public-dns-a.google.com."},
		// // Test 1 - ipv4 without port
		// {"8.8.8.8", "google-public-dns-a.google.com."},
		// // Test 2 - ipv6 with port
		// {"[2001:4860:4860::8888]:11", "google-public-dns-a.google.com."},
		// // Test 3 - ipv6 without port and brackets
		// {"2001:4860:4860::8888", "google-public-dns-a.google.com."},
		// Test 4 - no hostname available
		{"0.0.0.0", "0.0.0.0"},
	}

	for i, test := range tests {
		testPrefix := getTestPrefix(i)

		context.Req.RemoteAddr = test.inputRemoteAddr
		actualHostname := context.Hostname()

		if actualHostname != test.expectedHostname {
			t.Errorf(testPrefix+"Expected hostname %s, found %s", test.expectedHostname, actualHostname)
		}
	}
}

func TestEnv(t *testing.T) {
	context := getContextOrFail(t)

	name := "ENV_TEST_NAME"
	testValue := "TEST_VALUE"
	os.Setenv(name, testValue)

	notExisting := "ENV_TEST_NOT_EXISTING"
	os.Unsetenv(notExisting)

	invalidName := "ENV_TEST_INVALID_NAME"
	os.Setenv("="+invalidName, testValue)

	env := context.Env()
	if value := env[name]; value != testValue {
		t.Errorf("Expected env-variable %s value '%s', found '%s'",
			name, testValue, value)
	}

	if value, ok := env[notExisting]; ok {
		t.Errorf("Expected empty env-variable %s, found '%s'",
			notExisting, value)
	}

	for k, v := range env {
		if strings.Contains(k, invalidName) {
			t.Errorf("Expected invalid name not to be included in Env %s, found in key '%s'", invalidName, k)
		}
		if strings.Contains(v, invalidName) {
			t.Errorf("Expected invalid name not be be included in Env %s, found in value '%s'", invalidName, v)
		}
	}

	os.Unsetenv("=" + invalidName)
}

func TestIP(t *testing.T) {
	context := getContextOrFail(t)

	tests := []struct {
		inputRemoteAddr string
		expectedIP      string
	}{
		// Test 0 - ipv4 with port
		{"1.1.1.1:1111", "1.1.1.1"},
		// Test 1 - ipv4 without port
		{"1.1.1.1", "1.1.1.1"},
		// Test 2 - ipv6 with port
		{"[::1]:11", "::1"},
		// Test 3 - ipv6 without port and brackets
		{"[2001:db8:a0b:12f0::1]", "[2001:db8:a0b:12f0::1]"},
		// Test 4 - ipv6 with zone and port
		{`[fe80:1::3%eth0]:44`, `fe80:1::3%eth0`},
	}

	for i, test := range tests {
		testPrefix := getTestPrefix(i)

		context.Req.RemoteAddr = test.inputRemoteAddr
		actualIP := context.IP()

		if actualIP != test.expectedIP {
			t.Errorf(testPrefix+"Expected IP %s, found %s", test.expectedIP, actualIP)
		}
	}
}

type myIP string

func (ip myIP) mockInterfaces() ([]net.Addr, error) {
	a := net.ParseIP(string(ip))

	return []net.Addr{
		&net.IPNet{IP: a, Mask: nil},
	}, nil
}

func TestServerIP(t *testing.T) {
	context := getContextOrFail(t)

	tests := []string{
		// Test 0 - ipv4
		"1.1.1.1",
		// Test 1 - ipv6
		"2001:db8:a0b:12f0::1",
	}

	for i, expectedIP := range tests {
		testPrefix := getTestPrefix(i)

		// Mock the network interface
		ip := myIP(expectedIP)
		networkInterfacesFn = ip.mockInterfaces
		defer func() {
			networkInterfacesFn = net.InterfaceAddrs
		}()

		actualIP := context.ServerIP()

		if actualIP != expectedIP {
			t.Errorf("%sExpected IP \"%s\", found \"%s\".", testPrefix, expectedIP, actualIP)
		}
	}
}

func TestURL(t *testing.T) {
	context := getContextOrFail(t)

	inputURL := "http://localhost"
	context.Req.RequestURI = inputURL

	if inputURL != context.URI() {
		t.Errorf("Expected url %s, found %s", inputURL, context.URI())
	}
}

func TestHost(t *testing.T) {
	tests := []struct {
		input        string
		expectedHost string
		shouldErr    bool
	}{
		{
			input:        "localhost:123",
			expectedHost: "localhost",
			shouldErr:    false,
		},
		{
			input:        "localhost",
			expectedHost: "localhost",
			shouldErr:    false,
		},
		{
			input:        "[::]",
			expectedHost: "",
			shouldErr:    true,
		},
	}

	for _, test := range tests {
		testHostOrPort(t, true, test.input, test.expectedHost, test.shouldErr)
	}
}

func TestPort(t *testing.T) {
	tests := []struct {
		input        string
		expectedPort string
		shouldErr    bool
	}{
		{
			input:        "localhost:123",
			expectedPort: "123",
			shouldErr:    false,
		},
		{
			input:        "localhost",
			expectedPort: "80", // assuming 80 is the default port
			shouldErr:    false,
		},
		{
			input:        ":8080",
			expectedPort: "8080",
			shouldErr:    false,
		},
		{
			input:        "[::]",
			expectedPort: "",
			shouldErr:    true,
		},
	}

	for _, test := range tests {
		testHostOrPort(t, false, test.input, test.expectedPort, test.shouldErr)
	}
}

func testHostOrPort(t *testing.T, isTestingHost bool, input, expectedResult string, shouldErr bool) {
	context := getContextOrFail(t)

	context.Req.Host = input
	var actualResult, testedObject string
	var err error

	if isTestingHost {
		actualResult, err = context.Host()
		testedObject = "host"
	} else {
		actualResult, err = context.Port()
		testedObject = "port"
	}

	if shouldErr && err == nil {
		t.Errorf("Expected error, found nil!")
		return
	}

	if !shouldErr && err != nil {
		t.Errorf("Expected no error, found %s", err)
		return
	}

	if actualResult != expectedResult {
		t.Errorf("Expected %s %s, found %s", testedObject, expectedResult, actualResult)
	}
}

func TestMethod(t *testing.T) {
	context := getContextOrFail(t)

	method := "POST"
	context.Req.Method = method

	if method != context.Method() {
		t.Errorf("Expected method %s, found %s", method, context.Method())
	}

}

func TestContextPathMatches(t *testing.T) {
	context := getContextOrFail(t)

	tests := []struct {
		urlStr      string
		pattern     string
		shouldMatch bool
	}{
		// Test 0
		{
			urlStr:      "http://localhost/",
			pattern:     "",
			shouldMatch: true,
		},
		// Test 1
		{
			urlStr:      "http://localhost",
			pattern:     "",
			shouldMatch: true,
		},
		// Test 1
		{
			urlStr:      "http://localhost/",
			pattern:     "/",
			shouldMatch: true,
		},
		// Test 3
		{
			urlStr:      "http://localhost/?param=val",
			pattern:     "/",
			shouldMatch: true,
		},
		// Test 4
		{
			urlStr:      "http://localhost/dir1/dir2",
			pattern:     "/dir2",
			shouldMatch: false,
		},
		// Test 5
		{
			urlStr:      "http://localhost/dir1/dir2",
			pattern:     "/dir1",
			shouldMatch: true,
		},
		// Test 6
		{
			urlStr:      "http://localhost:444/dir1/dir2",
			pattern:     "/dir1",
			shouldMatch: true,
		},
		// Test 7
		{
			urlStr:      "http://localhost/dir1/dir2",
			pattern:     "*/dir2",
			shouldMatch: false,
		},
	}

	for i, test := range tests {
		testPrefix := getTestPrefix(i)
		var err error
		context.Req.URL, err = url.Parse(test.urlStr)
		if err != nil {
			t.Fatalf("Failed to prepare test URL from string %s! Error was: %s", test.urlStr, err)
		}

		matches := context.PathMatches(test.pattern)
		if matches != test.shouldMatch {
			t.Errorf(testPrefix+"Expected and actual result differ: expected to match [%t], actual matches [%t]", test.shouldMatch, matches)
		}
	}
}

func TestTruncate(t *testing.T) {
	context := getContextOrFail(t)
	tests := []struct {
		inputString string
		inputLength int
		expected    string
	}{
		// Test 0 - small length
		{
			inputString: "string",
			inputLength: 1,
			expected:    "s",
		},
		// Test 1 - exact length
		{
			inputString: "string",
			inputLength: 6,
			expected:    "string",
		},
		// Test 2 - bigger length
		{
			inputString: "string",
			inputLength: 10,
			expected:    "string",
		},
		// Test 3 - zero length
		{
			inputString: "string",
			inputLength: 0,
			expected:    "",
		},
		// Test 4 - negative, smaller length
		{
			inputString: "string",
			inputLength: -5,
			expected:    "tring",
		},
		// Test 5 - negative, exact length
		{
			inputString: "string",
			inputLength: -6,
			expected:    "string",
		},
		// Test 6 - negative, bigger length
		{
			inputString: "string",
			inputLength: -7,
			expected:    "string",
		},
	}

	for i, test := range tests {
		actual := context.Truncate(test.inputString, test.inputLength)
		if actual != test.expected {
			t.Errorf(getTestPrefix(i)+"Expected '%s', found '%s'. Input was Truncate(%q, %d)", test.expected, actual, test.inputString, test.inputLength)
		}
	}
}

func TestStripHTML(t *testing.T) {
	context := getContextOrFail(t)
	tests := []struct {
		input    string
		expected string
	}{
		// Test 0 - no tags
		{
			input:    `h1`,
			expected: `h1`,
		},
		// Test 1 - happy path
		{
			input:    `<h1>h1</h1>`,
			expected: `h1`,
		},
		// Test 2 - tag in quotes
		{
			input:    `<h1">">h1</h1>`,
			expected: `h1`,
		},
		// Test 3 - multiple tags
		{
			input:    `<h1><b>h1</b></h1>`,
			expected: `h1`,
		},
		// Test 4 - tags not closed
		{
			input:    `<h1`,
			expected: `<h1`,
		},
		// Test 5 - false start
		{
			input:    `<h1<b>hi`,
			expected: `<h1hi`,
		},
	}

	for i, test := range tests {
		actual := context.StripHTML(test.input)
		if actual != test.expected {
			t.Errorf(getTestPrefix(i)+"Expected %s, found %s. Input was StripHTML(%s)", test.expected, actual, test.input)
		}
	}
}

func TestStripExt(t *testing.T) {
	context := getContextOrFail(t)
	tests := []struct {
		input    string
		expected string
	}{
		// Test 0 - empty input
		{
			input:    "",
			expected: "",
		},
		// Test 1 - relative file with ext
		{
			input:    "file.ext",
			expected: "file",
		},
		// Test 2 - relative file without ext
		{
			input:    "file",
			expected: "file",
		},
		// Test 3 - absolute file without ext
		{
			input:    "/file",
			expected: "/file",
		},
		// Test 4 - absolute file with ext
		{
			input:    "/file.ext",
			expected: "/file",
		},
		// Test 5 - with ext but ends with /
		{
			input:    "/dir.ext/",
			expected: "/dir.ext/",
		},
		// Test 6 - file with ext under dir with ext
		{
			input:    "/dir.ext/file.ext",
			expected: "/dir.ext/file",
		},
	}

	for i, test := range tests {
		actual := context.StripExt(test.input)
		if actual != test.expected {
			t.Errorf(getTestPrefix(i)+"Expected %s, found %s. Input was StripExt(%q)", test.expected, actual, test.input)
		}
	}
}

func initTestContext() (Context, error) {
	body := bytes.NewBufferString("request body")
	request, err := http.NewRequest("GET", "https://localhost", body)
	if err != nil {
		return Context{}, err
	}
	res := httptest.NewRecorder()

	return Context{Root: http.Dir(os.TempDir()), responseHeader: res.Header(), Req: request}, nil
}

func getContextOrFail(t *testing.T) Context {
	context, err := initTestContext()
	if err != nil {
		t.Fatalf("Failed to prepare test context")
	}
	return context
}

func getTestPrefix(testN int) string {
	return fmt.Sprintf("Test [%d]: ", testN)
}

func TestTemplates(t *testing.T) {
	tests := []struct{ tmpl, expected string }{
		{`{{.ToUpper "aAA"}}`, "AAA"},
		{`{{"bbb" | .ToUpper}}`, "BBB"},
		{`{{.ToLower "CCc"}}`, "ccc"},
		{`{{range (.Split "a,b,c" ",")}}{{.}}{{end}}`, "abc"},
		{`{{range .Split "a,b,c" ","}}{{.}}{{end}}`, "abc"},
		{`{{range .Slice "a" "b" "c"}}{{.}}{{end}}`, "abc"},
		{`{{with .Map "A" "a" "B" "b" "c" "d"}}{{.A}}{{.B}}{{.c}}{{end}}`, "abd"},
	}
	for i, test := range tests {
		ctx := getContextOrFail(t)
		tmpl, err := template.New("").Parse(test.tmpl)
		if err != nil {
			t.Errorf("Test %d: %s", i, err)
			continue
		}
		buf := &bytes.Buffer{}
		err = tmpl.Execute(buf, ctx)
		if err != nil {
			t.Errorf("Test %d: %s", i, err)
			continue
		}
		if buf.String() != test.expected {
			t.Errorf("Test %d: Results do not match. '%s' != '%s'", i, buf.String(), test.expected)
		}
	}
}

func TestFiles(t *testing.T) {
	tests := []struct {
		fileNames []string
		inputBase string
		shouldErr bool
		verifyErr func(error) bool
	}{
		// Test 1 - directory and files exist
		{
			fileNames: []string{"file1", "file2"},
			shouldErr: false,
		},
		// Test 2 - directory exists, no files
		{
			fileNames: []string{},
			shouldErr: false,
		},
		// Test 3 - file or directory does not exist
		{
			fileNames: nil,
			inputBase: "doesNotExist",
			shouldErr: true,
			verifyErr: os.IsNotExist,
		},
		// Test 4 - directory and files exist, but path to a file
		{
			fileNames: []string{"file1", "file2"},
			inputBase: "file1",
			shouldErr: true,
			verifyErr: func(err error) bool {
				return strings.HasSuffix(err.Error(), "is not a directory")
			},
		},
		// Test 5 - try to leave Context Root
		{
			fileNames: nil,
			inputBase: filepath.Join("..", "..", "..", "..", "..", "etc"),
			shouldErr: true,
			verifyErr: os.IsNotExist,
		},
	}

	for i, test := range tests {
		context := getContextOrFail(t)
		testPrefix := getTestPrefix(i + 1)
		var dirPath string
		var err error

		// Create directory / files from test case.
		if test.fileNames != nil {
			dirPath, err = ioutil.TempDir(fmt.Sprintf("%s", context.Root), "caddy_ctxtest")
			if err != nil {
				os.RemoveAll(dirPath)
				t.Fatalf(testPrefix+"Expected no error creating directory, got: '%s'", err.Error())
			}

			for _, name := range test.fileNames {
				absFilePath := filepath.Join(dirPath, name)
				if err = ioutil.WriteFile(absFilePath, []byte(""), os.ModePerm); err != nil {
					os.RemoveAll(dirPath)
					t.Fatalf(testPrefix+"Expected no error creating file, got: '%s'", err.Error())
				}
			}
		}

		// Perform test case.
		input := filepath.ToSlash(filepath.Join(filepath.Base(dirPath), test.inputBase))
		actual, err := context.Files(input)
		if err != nil {
			if !test.shouldErr {
				t.Errorf(testPrefix+"Expected no error, got: '%s'", err.Error())
			} else if !test.verifyErr(err) {
				t.Errorf(testPrefix+"Could not verify error content, got: '%s'", err.Error())
			}
		} else if test.shouldErr {
			t.Errorf(testPrefix + "Expected error but had none")
		} else {
			numFiles := len(test.fileNames)
			// reflect.DeepEqual does not consider two empty slices to be equal
			if numFiles == 0 && len(actual) != 0 {
				t.Errorf(testPrefix+"Expected files %v, got: %v",
					test.fileNames, actual)
			} else {
				sort.Strings(actual)
				if numFiles > 0 && !reflect.DeepEqual(test.fileNames, actual) {
					t.Errorf(testPrefix+"Expected files %v, got: %v",
						test.fileNames, actual)
				}
			}
		}

		if dirPath != "" {
			if err := os.RemoveAll(dirPath); err != nil && !os.IsNotExist(err) {
				t.Fatalf(testPrefix+"Expected no error removing directory, got: '%s'", err.Error())
			}
		}
	}
}

func TestAddLink(t *testing.T) {
	for name, c := range map[string]struct {
		input       string
		expectLinks []string
	}{
		"oneLink": {
			input:       `{{.AddLink "</test.css>; rel=preload"}}`,
			expectLinks: []string{"</test.css>; rel=preload"},
		},
		"multipleLinks": {
			input:       `{{.AddLink "</test1.css>; rel=preload"}} {{.AddLink "</test2.css>; rel=meta"}}`,
			expectLinks: []string{"</test1.css>; rel=preload", "</test2.css>; rel=meta"},
		},
	} {
		c := c
		t.Run(name, func(t *testing.T) {
			ctx := getContextOrFail(t)
			tmpl, err := template.New("").Parse(c.input)
			if err != nil {
				t.Fatal(err)
			}
			err = tmpl.Execute(ioutil.Discard, ctx)
			if err != nil {
				t.Fatal(err)
			}
			if got := ctx.responseHeader["Link"]; !reflect.DeepEqual(got, c.expectLinks) {
				t.Errorf("Result not match: expect %v, but got %v", c.expectLinks, got)
			}
		})
	}
}

func TestTlsVersion(t *testing.T) {
	for _, test := range []struct {
		tlsState       *tls.ConnectionState
		expectedResult string
	}{
		{
			&tls.ConnectionState{Version: tls.VersionTLS10},
			"tls1.0",
		},
		{
			&tls.ConnectionState{Version: tls.VersionTLS11},
			"tls1.1",
		},
		{
			&tls.ConnectionState{Version: tls.VersionTLS12},
			"tls1.2",
		},
		// TLS not used
		{
			nil,
			"",
		},
		// Unsupported version
		{
			&tls.ConnectionState{Version: 0x0399},
			"",
		},
	} {
		context := getContextOrFail(t)
		context.Req.TLS = test.tlsState
		result := context.TLSVersion()
		if result != test.expectedResult {
			t.Errorf("Expected %s got %s", test.expectedResult, result)
		}
	}
}
