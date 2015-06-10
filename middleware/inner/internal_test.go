package inner

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mholt/caddy/middleware"
)

func TestInternal(t *testing.T) {
	im := Internal{
		Next:  middleware.HandlerFunc(internalTestHandlerFunc),
		Paths: []string{"/internal"},
	}

	tests := []struct {
		url          string
		expectedCode int
		expectedBody string
	}{
		{"/internal", http.StatusNotFound, ""},

		{"/public", 0, "/public"},
		{"/public/internal", 0, "/public/internal"},

		{"/redirect", 0, "/internal"},

		{"/cycle", http.StatusInternalServerError, ""},
	}

	for i, test := range tests {
		req, err := http.NewRequest("GET", test.url, nil)
		if err != nil {
			t.Fatalf("Test %d: Could not create HTTP request: %v", i, err)
		}

		rec := httptest.NewRecorder()
		code, err := im.ServeHTTP(rec, req)

		if code != test.expectedCode {
			t.Errorf("Test %d: Expected status code %d for %s, but got %d",
				i, test.expectedCode, test.url, code)
		}
		if rec.Body.String() != test.expectedBody {
			t.Errorf("Test %d: Expected body '%s' for %s, but got '%s'",
				i, test.expectedBody, test.url, rec.Body.String())
		}
	}
}

func internalTestHandlerFunc(w http.ResponseWriter, r *http.Request) (int, error) {
	switch r.URL.Path {
	case "/redirect":
		w.Header().Set("X-Accel-Redirect", "/internal")
	case "/cycle":
		w.Header().Set("X-Accel-Redirect", "/cycle")
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, r.URL.String())

	return 0, nil
}
