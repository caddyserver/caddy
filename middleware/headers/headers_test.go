package headers

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/mholt/caddy/middleware"
)

func TestHeaders(t *testing.T) {
	hostname, err := os.Hostname()
	if err != nil {
		t.Fatalf("Could not determine hostname: %v", err)
	}
	for i, test := range []struct {
		from  string
		name  string
		value string
	}{
		{"/a", "Foo", "Bar"},
		{"/a", "Bar", ""},
		{"/a", "Baz", ""},
		{"/a", "ServerName", hostname},
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
					{Name: "ServerName", Value: "{hostname}"},
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
