// Copyright 2015 Light Code Labs, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package basicauth

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/caddyhttp/httpserver"
)

func TestBasicAuth(t *testing.T) {
	var i int
	// This handler is registered for tests in which the only authorized user is
	// "okuser"
	upstreamHandler := func(w http.ResponseWriter, r *http.Request) (int, error) {
		remoteUser, _ := r.Context().Value(httpserver.RemoteUserCtxKey).(string)
		if remoteUser != "okuser" {
			t.Errorf("Test %d: expecting remote user 'okuser', got '%s'", i, remoteUser)
		}
		return http.StatusOK, nil
	}
	rws := []BasicAuth{
		{
			Next: httpserver.HandlerFunc(upstreamHandler),
			Rules: []Rule{
				{Username: "okuser", Password: PlainMatcher("okpass"),
					Resources: []string{"/testing"}, Realm: "Resources"},
			},
		},
		{
			Next: httpserver.HandlerFunc(upstreamHandler),
			Rules: []Rule{
				{Username: "okuser", Password: PlainMatcher("okpass"),
					Resources: []string{"/testing"}},
			},
		},
	}

	type testType struct {
		from     string
		result   int
		user     string
		password string
		haserror bool
	}

	tests := []testType{
		{"/testing", http.StatusOK, "okuser", "okpass", false},
		{"/testing", http.StatusUnauthorized, "baduser", "okpass", true},
		{"/testing", http.StatusUnauthorized, "okuser", "badpass", true},
		{"/testing", http.StatusUnauthorized, "OKuser", "okpass", true},
		{"/testing", http.StatusUnauthorized, "OKuser", "badPASS", true},
		{"/testing", http.StatusUnauthorized, "", "okpass", true},
		{"/testing", http.StatusUnauthorized, "okuser", "", true},
		{"/testing", http.StatusUnauthorized, "", "", true},
	}

	var test testType
	for _, rw := range rws {
		expectRealm := rw.Rules[0].Realm
		if expectRealm == "" {
			expectRealm = "Restricted" // Default if Realm not specified in rule
		}
		for i, test = range tests {
			req, err := http.NewRequest("GET", test.from, nil)
			if err != nil {
				t.Fatalf("Test %d: Could not create HTTP request: %v", i, err)
			}
			req.SetBasicAuth(test.user, test.password)

			rec := httptest.NewRecorder()
			result, err := rw.ServeHTTP(rec, req)
			if err != nil {
				if !test.haserror || !strings.HasPrefix(err.Error(), "BasicAuth: user") {
					t.Fatalf("Test %d: Could not ServeHTTP: %v", i, err)
				}
			}
			if result != test.result {
				t.Errorf("Test %d: Expected status code %d but was %d",
					i, test.result, result)
			}
			if test.result == http.StatusUnauthorized {
				headers := rec.Header()
				if val, ok := headers["Www-Authenticate"]; ok {
					if got, want := val[0], "Basic realm=\""+expectRealm+"\""; got != want {
						t.Errorf("Test %d: Www-Authenticate header should be '%s', got: '%s'", i, want, got)
					}
				} else {
					t.Errorf("Test %d: response should have a 'Www-Authenticate' header", i)
				}
			} else {
				if req.Header.Get("Authorization") == "" {
					// see issue #1508: https://github.com/caddyserver/caddy/issues/1508
					t.Errorf("Test %d: Expected Authorization header to be retained after successful auth, but was empty", i)
				}
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
		from     string
		result   int
		cred     string
		haserror bool
	}{
		{"/t", http.StatusOK, "t:p1", false},
		{"/t/t", http.StatusOK, "t:p1", false},
		{"/t/t", http.StatusOK, "t1:p2", false},
		{"/a", http.StatusOK, "t1:p2", false},
		{"/t/t", http.StatusUnauthorized, "t1:p3", true},
		{"/t", http.StatusUnauthorized, "t1:p2", true},
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
			if !test.haserror || !strings.HasPrefix(err.Error(), "BasicAuth: user") {
				t.Fatalf("Test %d: Could not ServeHTTP %v", i, err)
			}
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
		t.Skip("Error creating temp file, will skip htpassword test")
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

func TestOptionsMethod(t *testing.T) {
	rw := BasicAuth{
		Next: httpserver.HandlerFunc(contentHandler),
		Rules: []Rule{
			{Username: "username", Password: PlainMatcher("password"), Resources: []string{"/testing"}},
		},
	}

	req, err := http.NewRequest(http.MethodOptions, "/testing", nil)
	if err != nil {
		t.Fatalf("Could not create HTTP request: %v", err)
	}

	// add basic auth with invalid username
	// and password to make sure basic auth is ignored
	req.SetBasicAuth("invaliduser", "invalidpassword")

	rec := httptest.NewRecorder()
	result, err := rw.ServeHTTP(rec, req)
	if err != nil {
		t.Fatalf("Could not ServeHTTP: %v", err)
	}
	if result != http.StatusOK {
		t.Errorf("Expected status code %d but was %d", http.StatusOK, result)
	}
}
