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

	if myHandler.LogFile != "" {
		t.Errorf("Expected '%s' as the default LogFile", "")
	}
	if myHandler.LogRoller != nil {
		t.Errorf("Expected LogRoller to be nil, got: %v", *myHandler.LogRoller)
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
		}},
		{`errors errors.txt`, false, ErrorHandler{
			ErrorPages: map[int]string{},
			LogFile:    "errors.txt",
		}},
		{`errors visible`, false, ErrorHandler{
			ErrorPages: map[int]string{},
			Debug:      true,
		}},
		{`errors { log visible }`, false, ErrorHandler{
			ErrorPages: map[int]string{},
			Debug:      true,
		}},
		{`errors { log errors.txt
        404 404.html
        500 500.html
}`, false, ErrorHandler{
			LogFile: "errors.txt",
			ErrorPages: map[int]string{
				404: "404.html",
				500: "500.html",
			},
		}},
		{`errors { log errors.txt { size 2 age 10 keep 3 } }`, false, ErrorHandler{
			LogFile: "errors.txt",
			LogRoller: &httpserver.LogRoller{
				MaxSize:    2,
				MaxAge:     10,
				MaxBackups: 3,
				LocalTime:  true,
			},
			ErrorPages: map[int]string{},
		}},
		{`errors { log errors.txt {
            size 3
            age 11
            keep 5
        }
        404 404.html
        503 503.html
}`, false, ErrorHandler{
			LogFile: "errors.txt",
			ErrorPages: map[int]string{
				404: "404.html",
				503: "503.html",
			},
			LogRoller: &httpserver.LogRoller{
				MaxSize:    3,
				MaxAge:     11,
				MaxBackups: 5,
				LocalTime:  true,
			},
		}},
		{`errors { log errors.txt
        * generic_error.html
        404 404.html
        503 503.html
}`, false, ErrorHandler{
			LogFile:          "errors.txt",
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
			}},
		// Next two test cases is the detection of duplicate status codes
		{`errors {
        503 503.html
        503 503.html
}`, true, ErrorHandler{ErrorPages: map[int]string{}}},
		{`errors {
        * generic_error.html
        * generic_error.html
}`, true, ErrorHandler{ErrorPages: map[int]string{}}},
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
				actualErrorsRule, test.expectedErrorHandler)
		}
	}
}
