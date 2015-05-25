package basicauth

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mholt/caddy/middleware"
)

func TestBasicAuth(t *testing.T) {

	rw := BasicAuth{
		Next: middleware.HandlerFunc(contentHandler),
		Rules: []Rule{
			{Username: "test", Password: "ttest", Resources: []string{"/testing"}},
		},
	}

	tests := []struct {
		from   string
		result int
		cred   string
	}{
		{"/testing", http.StatusUnauthorized, "ttest:test"},
		{"/testing", http.StatusOK, "test:ttest"},
		{"/testing", http.StatusUnauthorized, ""},
	}

	for i, test := range tests {

		req, err := http.NewRequest("GET", test.from, nil)
		if err != nil {
			t.Fatalf("Test %d: Could not create HTTP request %v", i, err)
		}
		auth := "Basic " + base64.StdEncoding.EncodeToString([]byte(test.cred))
		req.Header.Set("Authorization", auth)

		rec := httptest.NewRecorder()
		result, err := rw.ServeHTTP(rec, req)
		if err != nil {
			t.Fatalf("Test %d: Could not ServeHTTP %v", i, err)
		}
		if result != test.result {
			t.Errorf("Test %d: Expected Header '%d' but was '%d'",
				i, test.result, result)
		}
		if result == http.StatusUnauthorized {
			headers := rec.Header()
			if val, ok := headers["Www-Authenticate"]; ok {
				if val[0] != "Basic" {
					t.Errorf("Test %d, Www-Authenticate should be %s provided %s", i, "Basic", val[0])
				}
			} else {
				t.Errorf("Test %d, should provide a header Www-Authenticate", i)
			}
		}

	}

}

func TestMultipleOverlappingRules(t *testing.T) {
	rw := BasicAuth{
		Next: middleware.HandlerFunc(contentHandler),
		Rules: []Rule{
			{Username: "t", Password: "p1", Resources: []string{"/t"}},
			{Username: "t1", Password: "p2", Resources: []string{"/t/t"}},
		},
	}

	tests := []struct {
		from   string
		result int
		cred   string
	}{
		{"/t", http.StatusOK, "t:p1"},
		{"/t/t", http.StatusOK, "t:p1"},
		{"/t/t", http.StatusOK, "t1:p2"},
		{"/a", http.StatusOK, "t1:p2"},
		{"/t/t", http.StatusUnauthorized, "t1:p3"},
		{"/t", http.StatusUnauthorized, "t1:p2"},
	}

	for i, test := range tests {

		req, err := http.NewRequest("GET", test.from, nil)
		if err != nil {
			t.Fatalf("Test %d: Could not create HTTP request %v", i, err)
		}
		auth := "Basic " + base64.StdEncoding.EncodeToString([]byte(test.cred))
		req.Header.Set("Authorization", auth)

		rec := httptest.NewRecorder()
		result, err := rw.ServeHTTP(rec, req)
		if err != nil {
			t.Fatalf("Test %d: Could not ServeHTTP %v", i, err)
		}
		if result != test.result {
			t.Errorf("Test %d: Expected Header '%d' but was '%d'",
				i, test.result, result)
		}

	}

}

func contentHandler(w http.ResponseWriter, r *http.Request) (int, error) {
	fmt.Fprintf(w, r.URL.String())
	return http.StatusOK, nil
}
