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
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestNewReplacer(t *testing.T) {
	w := httptest.NewRecorder()
	recordRequest := NewResponseRecorder(w)
	reader := strings.NewReader(`{"username": "dennis"}`)

	request, err := http.NewRequest("POST", "http://localhost", reader)
	if err != nil {
		t.Fatal("Request Formation Failed\n")
	}
	rep := NewReplacer(request, recordRequest, "")

	switch v := rep.(type) {
	case *replacer:
		if v.getSubstitution("{host}") != "localhost" {
			t.Error("Expected host to be localhost")
		}
		if v.getSubstitution("{method}") != "POST" {
			t.Error("Expected request method  to be POST")
		}
	default:
		t.Fatalf("Expected *replacer underlying Replacer type, got: %#v", rep)
	}
}

func TestReplace(t *testing.T) {
	w := httptest.NewRecorder()
	recordRequest := NewResponseRecorder(w)
	reader := strings.NewReader(`{"username": "dennis"}`)

	request, err := http.NewRequest("POST", "http://localhost/?foo=bar", reader)
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	ctx := context.WithValue(request.Context(), OriginalURLCtxKey, *request.URL)
	request = request.WithContext(ctx)

	request.Header.Set("Custom", "foobarbaz")
	request.Header.Set("ShorterVal", "1")
	repl := NewReplacer(request, recordRequest, "-")
	// add some headers after creating replacer
	request.Header.Set("CustomAdd", "caddy")
	request.Header.Set("Cookie", "foo=bar; taste=delicious")

	// add some respons headers
	recordRequest.Header().Set("Custom", "CustomResponseHeader")

	hostname, err := os.Hostname()
	if err != nil {
		t.Fatalf("Failed to determine hostname: %v", err)
	}

	old := now
	now = func() time.Time {
		return time.Date(2006, 1, 2, 15, 4, 5, 02, time.FixedZone("hardcoded", -7))
	}
	defer func() {
		now = old
	}()
	testCases := []struct {
		template string
		expect   string
	}{
		{"This hostname is {hostname}", "This hostname is " + hostname},
		{"This host is {host}.", "This host is localhost."},
		{"This request method is {method}.", "This request method is POST."},
		{"The response status is {status}.", "The response status is 200."},
		{"{when}", "02/Jan/2006:15:04:05 +0000"},
		{"{when_iso}", "2006-01-02T15:04:12Z"},
		{"{when_unix}", "1136214252"},
		{"The Custom header is {>Custom}.", "The Custom header is foobarbaz."},
		{"The CustomAdd header is {>CustomAdd}.", "The CustomAdd header is caddy."},
		{"The Custom response header is {<Custom}.", "The Custom response header is CustomResponseHeader."},
		{"Bad {>Custom placeholder", "Bad {>Custom placeholder"},
		{"The request is {request}.", "The request is POST /?foo=bar HTTP/1.1\\r\\nHost: localhost\\r\\n" +
			"Cookie: foo=bar; taste=delicious\\r\\nCustom: foobarbaz\\r\\nCustomadd: caddy\\r\\n" +
			"Shorterval: 1\\r\\n\\r\\n."},
		{"The cUsToM header is {>cUsToM}...", "The cUsToM header is foobarbaz..."},
		{"The cUsToM response header is {<CuSTom}.", "The cUsToM response header is CustomResponseHeader."},
		{"The Non-Existent header is {>Non-Existent}.", "The Non-Existent header is -."},
		{"Bad {host placeholder...", "Bad {host placeholder..."},
		{"Bad {>Custom placeholder", "Bad {>Custom placeholder"},
		{"Bad {>Custom placeholder {>ShorterVal}", "Bad -"},
		{"Bad {}", "Bad -"},
		{"Cookies are {~taste}", "Cookies are delicious"},
		{"Missing cookie is {~missing}", "Missing cookie is -"},
		{"Query string is {query}", "Query string is foo=bar"},
		{"Query string value for foo is {?foo}", "Query string value for foo is bar"},
		{"Missing query string argument is {?missing}", "Missing query string argument is "},
	}

	for _, c := range testCases {
		if expected, actual := c.expect, repl.Replace(c.template); expected != actual {
			t.Errorf("for template '%s', expected '%s', got '%s'", c.template, expected, actual)
		}
	}

	complexCases := []struct {
		template     string
		replacements map[string]string
		expect       string
	}{
		{
			"/a{1}/{2}",
			map[string]string{
				"{1}": "12",
				"{2}": "",
			},
			"/a12/"},
	}

	for _, c := range complexCases {
		repl := &replacer{
			customReplacements: c.replacements,
		}
		if expected, actual := c.expect, repl.Replace(c.template); expected != actual {
			t.Errorf("for template '%s', expected '%s', got '%s'", c.template, expected, actual)
		}
	}
}

func TestResponseRecorderNil(t *testing.T) {

	reader := strings.NewReader(`{"username": "dennis"}`)

	request, err := http.NewRequest("POST", "http://localhost/?foo=bar", reader)
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}

	request.Header.Set("Custom", "foobarbaz")
	repl := NewReplacer(request, nil, "-")
	// add some headers after creating replacer
	request.Header.Set("CustomAdd", "caddy")
	request.Header.Set("Cookie", "foo=bar; taste=delicious")

	old := now
	now = func() time.Time {
		return time.Date(2006, 1, 2, 15, 4, 5, 02, time.FixedZone("hardcoded", -7))
	}
	defer func() {
		now = old
	}()
	testCases := []struct {
		template string
		expect   string
	}{
		{"The Custom response header is {<Custom}.", "The Custom response header is -."},
	}

	for _, c := range testCases {
		if expected, actual := c.expect, repl.Replace(c.template); expected != actual {
			t.Errorf("for template '%s', expected '%s', got '%s'", c.template, expected, actual)
		}
	}

}

func TestSet(t *testing.T) {
	w := httptest.NewRecorder()
	recordRequest := NewResponseRecorder(w)
	reader := strings.NewReader(`{"username": "dennis"}`)

	request, err := http.NewRequest("POST", "http://localhost", reader)
	if err != nil {
		t.Fatalf("Request Formation Failed: %s\n", err.Error())
	}
	repl := NewReplacer(request, recordRequest, "")

	repl.Set("host", "getcaddy.com")
	repl.Set("method", "GET")
	repl.Set("status", "201")
	repl.Set("variable", "value")

	if repl.Replace("This host is {host}") != "This host is getcaddy.com" {
		t.Error("Expected host replacement failed")
	}
	if repl.Replace("This request method is {method}") != "This request method is GET" {
		t.Error("Expected method replacement failed")
	}
	if repl.Replace("The response status is {status}") != "The response status is 201" {
		t.Error("Expected status replacement failed")
	}
	if repl.Replace("The value of variable is {variable}") != "The value of variable is value" {
		t.Error("Expected variable replacement failed")
	}
}

// Test function to test that various placeholders hold correct values after a rewrite
// has been performed.  The NewRequest actually contains the rewritten value.
func TestPathRewrite(t *testing.T) {
	w := httptest.NewRecorder()
	recordRequest := NewResponseRecorder(w)
	reader := strings.NewReader(`{"username": "dennis"}`)

	request, err := http.NewRequest("POST", "http://getcaddy.com/index.php?key=value", reader)
	if err != nil {
		t.Fatalf("Request Formation Failed: %s\n", err.Error())
	}
	urlCopy := *request.URL
	urlCopy.Path = "a/custom/path.php"
	ctx := context.WithValue(request.Context(), OriginalURLCtxKey, urlCopy)
	request = request.WithContext(ctx)

	repl := NewReplacer(request, recordRequest, "")

	if got, want := repl.Replace("This path is '{path}'"), "This path is 'a/custom/path.php'"; got != want {
		t.Errorf("{path} replacement failed; got '%s', want '%s'", got, want)
	}

	if got, want := repl.Replace("This path is {rewrite_path}"), "This path is /index.php"; got != want {
		t.Errorf("{rewrite_path} replacement failed; got '%s', want '%s'", got, want)
	}
	if got, want := repl.Replace("This path is '{uri}'"), "This path is 'a/custom/path.php?key=value'"; got != want {
		t.Errorf("{uri} replacement failed; got '%s', want '%s'", got, want)
	}

	if got, want := repl.Replace("This path is {rewrite_uri}"), "This path is /index.php?key=value"; got != want {
		t.Errorf("{rewrite_uri} replacement failed; got '%s', want '%s'", got, want)
	}

}

func TestRound(t *testing.T) {
	var tests = map[time.Duration]time.Duration{
		// 599.935µs -> 560µs
		559935 * time.Nanosecond: 560 * time.Microsecond,
		// 1.55ms    -> 2ms
		1550 * time.Microsecond: 2 * time.Millisecond,
		// 1.5555s   -> 1.556s
		1555500 * time.Microsecond: 1556 * time.Millisecond,
		// 1m2.0035s -> 1m2.004s
		62003500 * time.Microsecond: 62004 * time.Millisecond,
	}

	for dur, expected := range tests {
		rounded := roundDuration(dur)
		if rounded != expected {
			t.Errorf("Expected %v, Got %v", expected, rounded)
		}
	}
}

func TestMillisecondConverstion(t *testing.T) {
	var testCases = map[time.Duration]int64{
		2 * time.Second:           2000,
		9039492 * time.Nanosecond: 9,
		1000 * time.Microsecond:   1,
		127 * time.Nanosecond:     0,
		0 * time.Millisecond:      0,
		255 * time.Millisecond:    255,
	}

	for dur, expected := range testCases {
		numMillisecond := convertToMilliseconds(dur)
		if numMillisecond != expected {
			t.Errorf("Expected %v. Got %v", expected, numMillisecond)
		}
	}
}
