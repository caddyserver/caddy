package log

import (
	"bytes"
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
		Format:    DefaultLogFormat + " {testval}",
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
