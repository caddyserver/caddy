package errors

import (
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
	tests := []struct {
		inputErrorsRules     string
		shouldErr            bool
		expectedErrorHandler ErrorHandler
	}{
		{`errors`, false, ErrorHandler{
			LogFile: "",
		}},
		{`errors errors.txt`, false, ErrorHandler{
			LogFile: "errors.txt",
		}},
		{`errors visible`, false, ErrorHandler{
			LogFile: "",
			Debug:   true,
		}},
		{`errors { log visible }`, false, ErrorHandler{
			LogFile: "",
			Debug:   true,
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
		// Next two test cases is the detection of duplicate status codes
		{`errors {
        503 503.html
        503 503.html
}`, true, ErrorHandler{}},
		{`errors {
        * generic_error.html
        * generic_error.html
}`, true, ErrorHandler{}},
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
		if actualErrorsRule.LogFile != test.expectedErrorHandler.LogFile {
			t.Errorf("Test %d expected LogFile to be %s, but got %s",
				i, test.expectedErrorHandler.LogFile, actualErrorsRule.LogFile)
		}
		if actualErrorsRule.Debug != test.expectedErrorHandler.Debug {
			t.Errorf("Test %d expected Debug to be %v, but got %v",
				i, test.expectedErrorHandler.Debug, actualErrorsRule.Debug)
		}
		if actualErrorsRule.LogRoller != nil && test.expectedErrorHandler.LogRoller == nil || actualErrorsRule.LogRoller == nil && test.expectedErrorHandler.LogRoller != nil {
			t.Fatalf("Test %d expected LogRoller to be %v, but got %v",
				i, test.expectedErrorHandler.LogRoller, actualErrorsRule.LogRoller)
		}
		if len(actualErrorsRule.ErrorPages) != len(test.expectedErrorHandler.ErrorPages) {
			t.Fatalf("Test %d expected %d no of Error pages, but got %d ",
				i, len(test.expectedErrorHandler.ErrorPages), len(actualErrorsRule.ErrorPages))
		}
		if actualErrorsRule.LogRoller != nil && test.expectedErrorHandler.LogRoller != nil {
			if actualErrorsRule.LogRoller.Filename != test.expectedErrorHandler.LogRoller.Filename {
				t.Fatalf("Test %d expected LogRoller Filename to be %s, but got %s",
					i, test.expectedErrorHandler.LogRoller.Filename, actualErrorsRule.LogRoller.Filename)
			}
			if actualErrorsRule.LogRoller.MaxAge != test.expectedErrorHandler.LogRoller.MaxAge {
				t.Fatalf("Test %d expected LogRoller MaxAge to be %d, but got %d",
					i, test.expectedErrorHandler.LogRoller.MaxAge, actualErrorsRule.LogRoller.MaxAge)
			}
			if actualErrorsRule.LogRoller.MaxBackups != test.expectedErrorHandler.LogRoller.MaxBackups {
				t.Fatalf("Test %d expected LogRoller MaxBackups to be %d, but got %d",
					i, test.expectedErrorHandler.LogRoller.MaxBackups, actualErrorsRule.LogRoller.MaxBackups)
			}
			if actualErrorsRule.LogRoller.MaxSize != test.expectedErrorHandler.LogRoller.MaxSize {
				t.Fatalf("Test %d expected LogRoller MaxSize to be %d, but got %d",
					i, test.expectedErrorHandler.LogRoller.MaxSize, actualErrorsRule.LogRoller.MaxSize)
			}
			if actualErrorsRule.LogRoller.LocalTime != test.expectedErrorHandler.LogRoller.LocalTime {
				t.Fatalf("Test %d expected LogRoller LocalTime to be %t, but got %t",
					i, test.expectedErrorHandler.LogRoller.LocalTime, actualErrorsRule.LogRoller.LocalTime)
			}
		}
		if actualErrorsRule.GenericErrorPage != test.expectedErrorHandler.GenericErrorPage {
			t.Fatalf("Test %d expected GenericErrorPage to be %v, but got %v",
				i, test.expectedErrorHandler.GenericErrorPage, actualErrorsRule.GenericErrorPage)
		}
	}

}
