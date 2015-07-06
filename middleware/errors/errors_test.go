package errors

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mholt/caddy/middleware"
)

func TestErrors(t *testing.T) {
	// create a temporary page
	path := filepath.Join(os.TempDir(), "errors_test.html")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(path)

	const content = "This is a error page"
	_, err = f.WriteString(content)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	buf := bytes.Buffer{}
	em := ErrorHandler{
		ErrorPages: make(map[int]string),
		Log:        log.New(&buf, "", 0),
	}
	em.ErrorPages[http.StatusNotFound] = path
	em.ErrorPages[http.StatusForbidden] = "not_exist_file"
	_, notExistErr := os.Open("not_exist_file")

	testErr := errors.New("test error")
	tests := []struct {
		next         middleware.Handler
		expectedCode int
		expectedBody string
		expectedLog  string
		expectedErr  error
	}{
		{
			next:         genErrorHandler(http.StatusOK, nil, "normal"),
			expectedCode: http.StatusOK,
			expectedBody: "normal",
			expectedLog:  "",
			expectedErr:  nil,
		},
		{
			next:         genErrorHandler(http.StatusMovedPermanently, testErr, ""),
			expectedCode: http.StatusMovedPermanently,
			expectedBody: "",
			expectedLog:  fmt.Sprintf("[ERROR %d %s] %v\n", http.StatusMovedPermanently, "/", testErr),
			expectedErr:  testErr,
		},
		{
			next:         genErrorHandler(http.StatusBadRequest, nil, ""),
			expectedCode: 0,
			expectedBody: fmt.Sprintf("%d %s\n", http.StatusBadRequest,
				http.StatusText(http.StatusBadRequest)),
			expectedLog: "",
			expectedErr: nil,
		},
		{
			next:         genErrorHandler(http.StatusNotFound, nil, ""),
			expectedCode: 0,
			expectedBody: content,
			expectedLog:  "",
			expectedErr:  nil,
		},
		{
			next:         genErrorHandler(http.StatusForbidden, nil, ""),
			expectedCode: 0,
			expectedBody: fmt.Sprintf("%d %s\n", http.StatusForbidden,
				http.StatusText(http.StatusForbidden)),
			expectedLog: fmt.Sprintf("HTTP %d could not load error page %s: %v\n",
				http.StatusForbidden, "not_exist_file", notExistErr),
			expectedErr: nil,
		},
	}

	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	for i, test := range tests {
		em.Next = test.next
		buf.Reset()
		rec := httptest.NewRecorder()
		code, err := em.ServeHTTP(rec, req)

		if err != test.expectedErr {
			t.Errorf("Test %d: Expected error %v, but got %v",
				i, test.expectedErr, err)
		}
		if code != test.expectedCode {
			t.Errorf("Test %d: Expected status code %d, but got %d",
				i, test.expectedCode, code)
		}
		if body := rec.Body.String(); body != test.expectedBody {
			t.Errorf("Test %d: Expected body %q, but got %q",
				i, test.expectedBody, body)
		}
		if log := buf.String(); !strings.Contains(log, test.expectedLog) {
			t.Errorf("Test %d: Expected log %q, but got %q",
				i, test.expectedLog, log)
		}
	}
}

func genErrorHandler(status int, err error, body string) middleware.Handler {
	return middleware.HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) {
		fmt.Fprint(w, body)
		return status, err
	})
}
