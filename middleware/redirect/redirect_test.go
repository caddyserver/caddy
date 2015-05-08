package redirect

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mholt/caddy/middleware"
)

func TestRedirect(t *testing.T) {
	re := Redirect{
		Next: middleware.HandlerFunc(urlPrinter),
		Rules: []Rule{
			{From: "/from", To: "/to"},
			{From: "/a", To: "/b"},
		},
	}
	tests := []struct {
		from             string
		expectedLocation string
	}{
		{"/from", "/to"},
		{"/a", "/b"},
		{"/aa", ""},
		{"/", ""},
		{"/a?foo=bar", "/b"},
		{"/asdf?foo=bar", ""},
		{"/foo#bar", ""},
		{"/a#foo", "/b"},
	}

	for i, test := range tests {
		req, err := http.NewRequest("GET", test.from, nil)
		if err != nil {
			t.Fatalf("Test %d: Could not create HTTP request: %v", i, err)
		}

		rec := httptest.NewRecorder()
		re.ServeHTTP(rec, req)

		if rec.Header().Get("Location") != test.expectedLocation {
			t.Errorf("Test %d: Expected Location header to be %q but was %q",
				i, test.expectedLocation, rec.Header().Get("Location"))
		}

		var expectedBody string

		if test.expectedLocation != "" {
			expectedBody = "<a href=\"" + test.expectedLocation + "\"></a>.\n\n"
		} else {
			expectedBody = test.from
		}

		if rec.Body.String() != expectedBody {
			t.Errorf("Test %d: Expected body to be %q but was %q",
				i, expectedBody, rec.Body.String())
		}
	}
}

func urlPrinter(w http.ResponseWriter, r *http.Request) (int, error) {
	fmt.Fprintf(w, r.URL.String())
	return 0, nil
}
