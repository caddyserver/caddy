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

package log

import (
	"bytes"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mholt/caddy/caddyhttp/httpserver"
)

type erroringMiddleware struct{}

func (erroringMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	if rr, ok := w.(*httpserver.ResponseRecorder); ok {
		rr.Replacer.Set("testval", "foobar")
	}
	return http.StatusNotFound, nil
}

func TestLoggedStatus(t *testing.T) {
	var f bytes.Buffer
	var next erroringMiddleware
	rule := Rule{
		PathScope: "/",
		Entries: []*Entry{{
			Format: DefaultLogFormat + " {testval}",
			Log:    httpserver.NewTestLogger(&f),
		}},
	}

	logger := Logger{
		Rules: []*Rule{&rule},
		Next:  next,
	}

	r, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()

	status, err := logger.ServeHTTP(rec, r)
	if status != 0 {
		t.Errorf("Expected status to be 0, but was %d", status)
	}

	if err != nil {
		t.Errorf("Expected error to be nil, instead got: %v", err)
	}

	logged := f.String()
	if !strings.Contains(logged, "404 13") {
		t.Errorf("Expected log entry to contain '404 13', but it didn't: %s", logged)
	}

	// check custom placeholder
	if !strings.Contains(logged, "foobar") {
		t.Errorf("Expected the log entry to contain 'foobar' (custom placeholder), but it didn't: %s", logged)
	}
}

func TestLogRequestBody(t *testing.T) {
	var got bytes.Buffer
	logger := Logger{
		Rules: []*Rule{{
			PathScope: "/",
			Entries: []*Entry{{
				Format: "{request_body}",
				Log:    httpserver.NewTestLogger(&got),
			}},
		}},
		Next: httpserver.HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) {
			// drain up body
			if _, err := ioutil.ReadAll(r.Body); err != nil {
				log.Println("[ERROR] failed to read request body: ", err)
			}
			return 0, nil
		}),
	}

	for i, c := range []struct {
		body   string
		expect string
	}{
		{"", "\n"},
		{"{hello} world!", "{hello} world!\n"},
		{func() string {
			length := httpserver.MaxLogBodySize + 100
			b := make([]byte, length)
			for i := 0; i < length; i++ {
				b[i] = 0xab
			}
			return string(b)
		}(), func() string {
			b := make([]byte, httpserver.MaxLogBodySize)
			for i := 0; i < httpserver.MaxLogBodySize; i++ {
				b[i] = 0xab
			}
			return string(b) + "\n"
		}(),
		},
	} {
		got.Reset()
		r := httptest.NewRequest("POST", "/", bytes.NewBufferString(c.body))
		r.Header.Set("Content-Type", "application/json")
		status, err := logger.ServeHTTP(httptest.NewRecorder(), r)
		if status != 0 {
			t.Errorf("case %d: Expected status to be 0, but was %d", i, status)
		}
		if err != nil {
			t.Errorf("case %d: Expected error to be nil, instead got: %v", i, err)
		}
		if got.String() != c.expect {
			t.Errorf("case %d: Expected body %q, but got %q", i, c.expect, got.String())
		}
	}
}

func TestMultiEntries(t *testing.T) {
	var (
		got1 bytes.Buffer
		got2 bytes.Buffer
	)
	logger := Logger{
		Rules: []*Rule{{
			PathScope: "/",
			Entries: []*Entry{
				{
					Format: "foo {request_body}",
					Log:    httpserver.NewTestLogger(&got1),
				},
				{
					Format: "{method} {request_body}",
					Log:    httpserver.NewTestLogger(&got2),
				},
			},
		}},
		Next: httpserver.HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) {
			// drain up body
			if _, err := ioutil.ReadAll(r.Body); err != nil {
				log.Println("[ERROR] failed to read request body: ", err)
			}
			return 0, nil
		}),
	}

	r, err := http.NewRequest("POST", "/", bytes.NewBufferString("hello world"))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	status, err := logger.ServeHTTP(httptest.NewRecorder(), r)
	if status != 0 {
		t.Errorf("Expected status to be 0, but was %d", status)
	}
	if err != nil {
		t.Errorf("Expected error to be nil, instead got: %v", err)
	}
	if got, expect := got1.String(), "foo hello world\n"; got != expect {
		t.Errorf("Expected %q, but got %q", expect, got)
	}
	if got, expect := got2.String(), "POST hello world\n"; got != expect {
		t.Errorf("Expected %q, but got %q", expect, got)
	}
}

func TestLogExcept(t *testing.T) {
	tests := []struct {
		LogRules  []Rule
		logPath   string
		shouldLog bool
	}{
		{[]Rule{{
			PathScope: "/",
			Entries: []*Entry{{
				Log: &httpserver.Logger{

					Exceptions: []string{"/soup"},
				},
				Format: DefaultLogFormat,
			}},
		}}, `/soup`, false},
		{[]Rule{{
			PathScope: "/",
			Entries: []*Entry{{
				Log: &httpserver.Logger{

					Exceptions: []string{"/tart"},
				},
				Format: DefaultLogFormat,
			}},
		}}, `/soup`, true},
		{[]Rule{{
			PathScope: "/",
			Entries: []*Entry{{
				Log: &httpserver.Logger{

					Exceptions: []string{"/soup"},
				},
				Format: DefaultLogFormat,
			}},
		}}, `/tomatosoup`, true},
		{[]Rule{{
			PathScope: "/",
			Entries: []*Entry{{
				Log: &httpserver.Logger{

					Exceptions: []string{"/pie/"},
				},
				Format: DefaultLogFormat,
			}},
			// Check exception with a trailing slash does not match without
		}}, `/pie`, true},
		{[]Rule{{
			PathScope: "/",
			Entries: []*Entry{{
				Log: &httpserver.Logger{

					Exceptions: []string{"/pie.php"},
				},
				Format: DefaultLogFormat,
			}},
		}}, `/pie`, true},
		{[]Rule{{
			PathScope: "/",
			Entries: []*Entry{{
				Log: &httpserver.Logger{

					Exceptions: []string{"/pie"},
				},
				Format: DefaultLogFormat,
			}},
			// Check that a word without trailing slash will match a filename
		}}, `/pie.php`, false},
	}
	for i, test := range tests {
		for _, LogRule := range test.LogRules {
			for _, e := range LogRule.Entries {
				shouldLog := e.Log.ShouldLog(test.logPath)
				if shouldLog != test.shouldLog {
					t.Fatalf("Test  %d expected shouldLog=%t but got shouldLog=%t,", i, test.shouldLog, shouldLog)
				}
			}
		}

	}
}
