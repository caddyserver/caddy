package log

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type erroringMiddleware struct{}

func (erroringMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	return http.StatusNotFound, nil
}

func TestLoggedStatus(t *testing.T) {
	var f bytes.Buffer
	var next erroringMiddleware
	rule := Rule{
		PathScope: "/",
		Format:    DefaultLogFormat,
		Log:       log.New(&f, "", 0),
	}

	logger := Logger{
		Rules: []Rule{rule},
		Next:  next,
	}

	r, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()

	status, err := logger.ServeHTTP(rec, r)
	if status != 0 {
		t.Error("Expected status to be 0 - was", status)
	}

	logged := f.String()
	if !strings.Contains(logged, "404 13") {
		t.Error("Expected 404 to be logged. Logged string -", logged)
	}
}
