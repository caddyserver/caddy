package rewrite

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mholt/caddy/middleware"
)

func TestRewrite(t *testing.T) {
	rw := Rewrite{
		Next: middleware.HandlerFunc(urlPrinter),
		Rules: []Rule{
			{From: "/from", To: "/to"},
			{From: "/a", To: "/b"},
		},
	}
	tests := []struct {
		from       string
		expectedTo string
	}{
		{"/from", "/to"},
		{"/a", "/b"},
		{"/aa", "/aa"},
		{"/", "/"},
		{"/a?foo=bar", "/b?foo=bar"},
		{"/asdf?foo=bar", "/asdf?foo=bar"},
		{"/foo#bar", "/foo#bar"},
		{"/a#foo", "/b#foo"},
	}

	for i, test := range tests {
		req, err := http.NewRequest("GET", test.from, nil)
		if err != nil {
			t.Fatalf("Test %d: Could not create HTTP request: %v", i, err)
		}

		rec := httptest.NewRecorder()
		rw.ServeHTTP(rec, req)

		if rec.Body.String() != test.expectedTo {
			t.Errorf("Test %d: Expected URL to be '%s' but was '%s'",
				i, test.expectedTo, rec.Body.String())
		}
	}
}

func urlPrinter(w http.ResponseWriter, r *http.Request) (int, error) {
	fmt.Fprintf(w, r.URL.String())
	return 0, nil
}
