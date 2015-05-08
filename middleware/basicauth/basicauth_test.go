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
		{"/testing", http.StatusOK, "test:ttest"},
		{"/testing", http.StatusUnauthorized, ""},

	}

	//auth := "Basic " + base64.StdEncoding.EncodeToString([]byte("foo:bar"))
	for i, test := range tests {

		
		req, err := http.NewRequest("GET", test.from, nil)
		if err != nil {
			t.Fatalf("Test %d: Could not create HTTP request %v", i, err)
		}
		auth := "Basic " + base64.StdEncoding.EncodeToString([]byte(test.cred))
		req.Header.Set("Authorization", auth)

		rec := httptest.NewRecorder()
		rw.ServeHTTP(rec, req)

		if rec.Code != test.result {
			t.Errorf("Test %d: Expected Header '%d' but was '%d'",
				i, test.result, rec.Code)
		}

	}

}

func contentHandler(w http.ResponseWriter, r *http.Request) (int, error) {
	fmt.Fprintf(w, r.URL.String())
	return 0, nil
}