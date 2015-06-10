package redirect

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mholt/caddy/middleware"
)

func TestMetaRedirect(t *testing.T) {
	re := Redirect{
		Rules: []Rule{
			{From: "/", Meta: true, To: "https://example.com/"},
			{From: "/whatever", Meta: true, To: "https://example.com/whatever"},
		},
	}

	for i, test := range re.Rules {
		req, err := http.NewRequest("GET", test.From, nil)
		if err != nil {
			t.Fatalf("Test %d: Could not create HTTP request: %v", i, err)
		}

		rec := httptest.NewRecorder()
		re.ServeHTTP(rec, req)

		body, err := ioutil.ReadAll(rec.Body)
		if err != nil {
			t.Fatalf("Test %d: Could not read HTTP response body: %v", i, err)
		}
		expectedSnippet := `<meta http-equiv="refresh" content="0;URL='` + test.To + `'">`
		if !bytes.Contains(body, []byte(expectedSnippet)) {
			t.Errorf("Test %d: Expected Response Body to contain %q but was %q",
				i, expectedSnippet, body)
		}
	}
}

func TestRedirect(t *testing.T) {
	for i, test := range []struct {
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
	} {
		var nextCalled bool

		re := Redirect{
			Next: middleware.HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) {
				nextCalled = true
				return 0, nil
			}),
			Rules: []Rule{
				{From: "/from", To: "/to"},
				{From: "/a", To: "/b"},
			},
		}

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

		if nextCalled && test.expectedLocation != "" {
			t.Errorf("Test %d: Next handler was unexpectedly called", i)
		}
	}
}
