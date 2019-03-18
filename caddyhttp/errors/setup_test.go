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

package errors

import (
	"path/filepath"
	"reflect"
	"testing"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func TestSetup(t *testing.T) {
	c := caddy.NewTestController("http", `errors`)
	err := setup(c)
	if err != nil {
		t.Errorf("Expected no errors, got: %v", err)
	}
	mids := httpserver.GetConfig(c).Middleware()
	if len(mids) == 0 {
		t.Fatal("Expected middlewares, was nil instead")
	}

	handler := mids[0](httpserver.EmptyNext)
	myHandler, ok := handler.(*ErrorHandler)
	if !ok {
		t.Fatalf("Expected handler to be type ErrorHandler, got: %#v", handler)
	}

	expectedLogger := &httpserver.Logger{}

	if !reflect.DeepEqual(expectedLogger, myHandler.Log) {
		t.Errorf("Expected '%v' as the default Log, got: '%v'", expectedLogger, myHandler.Log)
	}

	if !httpserver.SameNext(myHandler.Next, httpserver.EmptyNext) {
		t.Error("'Next' field of handler was not set properly")
	}

	// Test Startup function -- TODO
	// if len(c.Startup) == 0 {
	// 	t.Fatal("Expected 1 startup function, had 0")
	// }
	// c.Startup[0]()
	// if myHandler.Log == nil {
	// 	t.Error("Expected Log to be non-nil after startup because Debug is not enabled")
	// }
}

func TestErrorsParse(t *testing.T) {
	testAbs, err := filepath.Abs("./404.html")
	if err != nil {
		t.Error(err)
	}
	tests := []struct {
		inputErrorsRules     string
		shouldErr            bool
		expectedErrorHandler ErrorHandler
	}{
		{`errors`, false, ErrorHandler{
			ErrorPages: map[int]string{},
			Log:        &httpserver.Logger{},
		}},
		{`errors errors.txt`, false, ErrorHandler{
			ErrorPages: map[int]string{},
			Log: &httpserver.Logger{
				Output: "errors.txt",
				Roller: httpserver.DefaultLogRoller(),
			},
		}},
		{`errors visible`, false, ErrorHandler{
			ErrorPages: map[int]string{},
			Debug:      true,
			Log:        &httpserver.Logger{},
		}},
		{`errors errors.txt {
        404 404.html
        500 500.html
}`, false, ErrorHandler{
			ErrorPages: map[int]string{
				404: "404.html",
				500: "500.html",
			},
			Log: &httpserver.Logger{
				Output: "errors.txt",
				Roller: httpserver.DefaultLogRoller(),
			},
		}},
		{`errors errors.txt {
			rotate_size 2
			rotate_age 10
			rotate_keep 3
			rotate_compress
		}`, false, ErrorHandler{
			ErrorPages: map[int]string{},
			Log: &httpserver.Logger{
				Output: "errors.txt", Roller: &httpserver.LogRoller{
					MaxSize:    2,
					MaxAge:     10,
					MaxBackups: 3,
					Compress:   true,
					LocalTime:  true,
				},
			},
		}},
		{`errors errors.txt {
		rotate_size 3
		rotate_age 11
		rotate_keep 5
        404 404.html
        503 503.html
}`, false, ErrorHandler{
			ErrorPages: map[int]string{
				404: "404.html",
				503: "503.html",
			},
			Log: &httpserver.Logger{
				Output: "errors.txt",
				Roller: &httpserver.LogRoller{
					MaxSize:    3,
					MaxAge:     11,
					MaxBackups: 5,
					Compress:   false,
					LocalTime:  true,
				},
			},
		}},
		{`errors errors.txt {
        * generic_error.html
        404 404.html
        503 503.html
}`, false, ErrorHandler{
			Log: &httpserver.Logger{
				Output: "errors.txt",
				Roller: httpserver.DefaultLogRoller(),
			},
			GenericErrorPage: "generic_error.html",
			ErrorPages: map[int]string{
				404: "404.html",
				503: "503.html",
			},
		}},
		// test absolute file path
		{`errors {
			404 ` + testAbs + `
		}`,
			false, ErrorHandler{
				ErrorPages: map[int]string{
					404: testAbs,
				},
				Log: &httpserver.Logger{},
			}},
		{`errors errors.txt { rotate_size 2 rotate_age 10 rotate_keep 3 rotate_compress }`,
			true, ErrorHandler{ErrorPages: map[int]string{}, Log: &httpserver.Logger{}}},
		{`errors errors.txt {
			rotate_compress invalid
		}`,
			true, ErrorHandler{ErrorPages: map[int]string{}, Log: &httpserver.Logger{}}},
		// Next two test cases is the detection of duplicate status codes
		{`errors {
			503 503.html
			503 503.html
		}`, true, ErrorHandler{ErrorPages: map[int]string{}, Log: &httpserver.Logger{}}},

		{`errors {
			* generic_error.html
			* generic_error.html
		}`, true, ErrorHandler{ErrorPages: map[int]string{}, Log: &httpserver.Logger{}}},
		{`errors /path error.txt {
			404 
		}`, true, ErrorHandler{ErrorPages: map[int]string{}, Log: &httpserver.Logger{}}},

		{`errors /path error.txt`, true, ErrorHandler{ErrorPages: map[int]string{}, Log: &httpserver.Logger{}}},
	}

	for i, test := range tests {
		actualErrorsRule, err := errorsParse(caddy.NewTestController("http", test.inputErrorsRules))

		if err == nil && test.shouldErr {
			t.Errorf("Test %d didn't error, but it should have", i)
		} else if err != nil && !test.shouldErr {
			t.Errorf("Test %d errored, but it shouldn't have; got '%v'", i, err)
		} else if err != nil && test.shouldErr {
			continue
		}
		if !reflect.DeepEqual(actualErrorsRule, &test.expectedErrorHandler) {
			t.Errorf("Test %d expect %v, but got %v", i,
				test.expectedErrorHandler, actualErrorsRule)
		}
	}
}
