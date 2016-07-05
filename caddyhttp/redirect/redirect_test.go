package redirect

import (
	"bytes"
	"crypto/tls"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func TestRedirect(t *testing.T) {
	for i, test := range []struct {
		from             string
		expectedLocation string
		expectedCode     int
	}{
		{"http://localhost/from", "/to", http.StatusMovedPermanently},
		{"http://localhost/a", "/b", http.StatusTemporaryRedirect},
		{"http://localhost/aa", "", http.StatusOK},
		{"http://localhost/", "", http.StatusOK},
		{"http://localhost/a?foo=bar", "/b", http.StatusTemporaryRedirect},
		{"http://localhost/asdf?foo=bar", "", http.StatusOK},
		{"http://localhost/foo#bar", "", http.StatusOK},
		{"http://localhost/a#foo", "/b", http.StatusTemporaryRedirect},

		// The scheme checks that were added to this package don't actually
		// help with redirects because of Caddy's design: a redirect middleware
		// for http will always be different than the redirect middleware for
		// https because they have to be on different listeners. These tests
		// just go to show extra bulletproofing, I guess.
		{"http://localhost/scheme", "https://localhost/scheme", http.StatusMovedPermanently},
		{"https://localhost/scheme", "", http.StatusOK},
		{"https://localhost/scheme2", "http://localhost/scheme2", http.StatusMovedPermanently},
		{"http://localhost/scheme2", "", http.StatusOK},
		{"http://localhost/scheme3", "https://localhost/scheme3", http.StatusMovedPermanently},
		{"https://localhost/scheme3", "", http.StatusOK},
	} {
		var nextCalled bool

		re := Redirect{
			Next: httpserver.HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) {
				nextCalled = true
				return 0, nil
			}),
			Rules: []Rule{
				{FromPath: "/from", To: "/to", Code: http.StatusMovedPermanently, RequestMatcher: httpserver.IfMatcher{}},
				{FromPath: "/a", To: "/b", Code: http.StatusTemporaryRedirect, RequestMatcher: httpserver.IfMatcher{}},

				// These http and https schemes would never actually be mixed in the same
				// redirect rule with Caddy because http and https schemes have different listeners,
				// so they don't share a redirect rule. So although these tests prove something
				// impossible with Caddy, it's extra bulletproofing at very little cost.
				{FromScheme: "http", FromPath: "/scheme", To: "https://localhost/scheme", Code: http.StatusMovedPermanently, RequestMatcher: httpserver.IfMatcher{}},
				{FromScheme: "https", FromPath: "/scheme2", To: "http://localhost/scheme2", Code: http.StatusMovedPermanently, RequestMatcher: httpserver.IfMatcher{}},
				{FromScheme: "", FromPath: "/scheme3", To: "https://localhost/scheme3", Code: http.StatusMovedPermanently, RequestMatcher: httpserver.IfMatcher{}},
			},
		}

		req, err := http.NewRequest("GET", test.from, nil)
		if err != nil {
			t.Fatalf("Test %d: Could not create HTTP request: %v", i, err)
		}
		if strings.HasPrefix(test.from, "https://") {
			req.TLS = new(tls.ConnectionState) // faux HTTPS
		}

		rec := httptest.NewRecorder()
		re.ServeHTTP(rec, req)

		if rec.Header().Get("Location") != test.expectedLocation {
			t.Errorf("Test %d: Expected Location header to be %q but was %q",
				i, test.expectedLocation, rec.Header().Get("Location"))
		}

		if rec.Code != test.expectedCode {
			t.Errorf("Test %d: Expected status code to be %d but was %d",
				i, test.expectedCode, rec.Code)
		}

		if nextCalled && test.expectedLocation != "" {
			t.Errorf("Test %d: Next handler was unexpectedly called", i)
		}
	}
}

func TestParametersRedirect(t *testing.T) {
	re := Redirect{
		Rules: []Rule{
			{FromPath: "/", Meta: false, To: "http://example.com{uri}", RequestMatcher: httpserver.IfMatcher{}},
		},
	}

	req, err := http.NewRequest("GET", "/a?b=c", nil)
	if err != nil {
		t.Fatalf("Test: Could not create HTTP request: %v", err)
	}

	rec := httptest.NewRecorder()
	re.ServeHTTP(rec, req)

	if rec.Header().Get("Location") != "http://example.com/a?b=c" {
		t.Fatalf("Test: expected location header %q but was %q", "http://example.com/a?b=c", rec.Header().Get("Location"))
	}

	re = Redirect{
		Rules: []Rule{
			{FromPath: "/", Meta: false, To: "http://example.com/a{path}?b=c&{query}", RequestMatcher: httpserver.IfMatcher{}},
		},
	}

	req, err = http.NewRequest("GET", "/d?e=f", nil)
	if err != nil {
		t.Fatalf("Test: Could not create HTTP request: %v", err)
	}

	re.ServeHTTP(rec, req)

	if "http://example.com/a/d?b=c&e=f" != rec.Header().Get("Location") {
		t.Fatalf("Test: expected location header %q but was %q", "http://example.com/a/d?b=c&e=f", rec.Header().Get("Location"))
	}
}

func TestMetaRedirect(t *testing.T) {
	re := Redirect{
		Rules: []Rule{
			{FromPath: "/whatever", Meta: true, To: "/something", RequestMatcher: httpserver.IfMatcher{}},
			{FromPath: "/", Meta: true, To: "https://example.com/", RequestMatcher: httpserver.IfMatcher{}},
		},
	}

	for i, test := range re.Rules {
		req, err := http.NewRequest("GET", test.FromPath, nil)
		if err != nil {
			t.Fatalf("Test %d: Could not create HTTP request: %v", i, err)
		}

		rec := httptest.NewRecorder()
		re.ServeHTTP(rec, req)

		body, err := ioutil.ReadAll(rec.Body)
		if err != nil {
			t.Fatalf("Test %d: Could not read HTTP response body: %v", i, err)
		}
		expectedSnippet := `<meta http-equiv="refresh" content="0; URL='` + test.To + `'">`
		if !bytes.Contains(body, []byte(expectedSnippet)) {
			t.Errorf("Test %d: Expected Response Body to contain %q but was %q",
				i, expectedSnippet, body)
		}
	}
}
