package headers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mholt/caddy/middleware"
)

func TestHeaders(t *testing.T) {
	for i, test := range []struct {
		from  string
		name  string
		value string
	}{
		{"/a", "Foo", "Bar"},
		{"/a", "Bar", ""},
		{"/a", "Baz", ""},
		{"/b", "Foo", ""},
		{"/b", "Bar", "Removed in /a"},
	} {
		he := Headers{
			Next: middleware.HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) {
				return 0, nil
			}),
			Rules: []Rule{
				{Path: "/a", Headers: []Header{
					{Name: "Foo", Value: "Bar"},
					{Name: "-Bar"},
				}},
			},
		}

		req, err := http.NewRequest("GET", test.from, nil)
		if err != nil {
			t.Fatalf("Test %d: Could not create HTTP request: %v", i, err)
		}

		rec := httptest.NewRecorder()
		rec.Header().Set("Bar", "Removed in /a")

		he.ServeHTTP(rec, req)

		if got := rec.Header().Get(test.name); got != test.value {
			t.Errorf("Test %d: Expected %s header to be %q but was %q",
				i, test.name, test.value, got)
		}
	}
}
