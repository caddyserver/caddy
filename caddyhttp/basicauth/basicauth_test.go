package basicauth

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func TestBasicAuth(t *testing.T) {
	rw := BasicAuth{
		Next: httpserver.HandlerFunc(contentHandler),
		Rules: []Rule{
			{Username: "okuser", Password: PlainMatcher("okpass"), Resources: []string{"/testing"}},
		},
	}

	tests := []struct {
		from     string
		result   int
		user     string
		password string
	}{
		{"/testing", http.StatusOK, "okuser", "okpass"},
		{"/testing", http.StatusUnauthorized, "baduser", "okpass"},
		{"/testing", http.StatusUnauthorized, "okuser", "badpass"},
		{"/testing", http.StatusUnauthorized, "OKuser", "okpass"},
		{"/testing", http.StatusUnauthorized, "OKuser", "badPASS"},
		{"/testing", http.StatusUnauthorized, "", "okpass"},
		{"/testing", http.StatusUnauthorized, "okuser", ""},
		{"/testing", http.StatusUnauthorized, "", ""},
	}

	for i, test := range tests {
		req, err := http.NewRequest("GET", test.from, nil)
		if err != nil {
			t.Fatalf("Test %d: Could not create HTTP request: %v", i, err)
		}
		req.SetBasicAuth(test.user, test.password)

		rec := httptest.NewRecorder()
		result, err := rw.ServeHTTP(rec, req)
		if err != nil {
			t.Fatalf("Test %d: Could not ServeHTTP: %v", i, err)
		}
		if result != test.result {
			t.Errorf("Test %d: Expected status code %d but was %d",
				i, test.result, result)
		}
		if test.result == http.StatusUnauthorized {
			headers := rec.Header()
			if val, ok := headers["Www-Authenticate"]; ok {
				if got, want := val[0], "Basic realm=\"Restricted\""; got != want {
					t.Errorf("Test %d: Www-Authenticate header should be '%s', got: '%s'", i, want, got)
				}
			} else {
				t.Errorf("Test %d: response should have a 'Www-Authenticate' header", i)
			}
		} else {
			if got, want := req.Header.Get("Authorization"), ""; got != want {
				t.Errorf("Test %d: Expected Authorization header to be stripped from request after successful authentication, but is: %s", i, got)
			}
		}
	}
}

func TestMultipleOverlappingRules(t *testing.T) {
	rw := BasicAuth{
		Next: httpserver.HandlerFunc(contentHandler),
		Rules: []Rule{
			{Username: "t", Password: PlainMatcher("p1"), Resources: []string{"/t"}},
			{Username: "t1", Password: PlainMatcher("p2"), Resources: []string{"/t/t"}},
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

func TestHtpasswd(t *testing.T) {
	htpasswdPasswd := "IedFOuGmTpT8"
	htpasswdFile := `sha1:{SHA}dcAUljwz99qFjYR0YLTXx0RqLww=
md5:$apr1$l42y8rex$pOA2VJ0x/0TwaFeAF9nX61`

	htfh, err := ioutil.TempFile("", "basicauth-")
	if err != nil {
		t.Skipf("Error creating temp file (%v), will skip htpassword test")
		return
	}
	defer os.Remove(htfh.Name())
	if _, err = htfh.Write([]byte(htpasswdFile)); err != nil {
		t.Fatalf("write htpasswd file %q: %v", htfh.Name(), err)
	}
	htfh.Close()

	for i, username := range []string{"sha1", "md5"} {
		rule := Rule{Username: username, Resources: []string{"/testing"}}

		siteRoot := filepath.Dir(htfh.Name())
		filename := filepath.Base(htfh.Name())
		if rule.Password, err = GetHtpasswdMatcher(filename, rule.Username, siteRoot); err != nil {
			t.Fatalf("GetHtpasswdMatcher(%q, %q): %v", htfh.Name(), rule.Username, err)
		}
		t.Logf("%d. username=%q", i, rule.Username)
		if !rule.Password(htpasswdPasswd) || rule.Password(htpasswdPasswd+"!") {
			t.Errorf("%d (%s) password does not match.", i, rule.Username)
		}
	}
}
