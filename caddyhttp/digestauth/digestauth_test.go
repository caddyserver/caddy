package digestauth

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func TestDigestAuth(t *testing.T) {
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
	rws := []DigestAuth{
		{
			Next: httpserver.HandlerFunc(upstreamHandler),
			Rules: []Rule{
				{Users: NewSimpleUserStore(map[string]string{"okuser": "okpass"}),
					Resources: []string{"/testing"}, Realm: "Resources"},
			},
		},
		{
			Next: httpserver.HandlerFunc(upstreamHandler),
			Rules: []Rule{
				{Users: NewSimpleUserStore(map[string]string{"okuser": "okpass"}),
					Resources: []string{"/testing"}, Realm: "Restricted"},
			},
		},
	}

	rws[0].Rules[0].Digester = NewDigestHandler(rws[0].Rules[0].Realm, nil, nil, rws[0].Rules[0].Users)
	rws[1].Rules[0].Digester = NewDigestHandler(rws[1].Rules[0].Realm, nil, nil, rws[1].Rules[0].Users)

	type testType struct {
		from     string
		result   int
		user     string
		password string
	}

	tests := []testType{
		{"/testing", http.StatusOK, "okuser", "okpass"},
		{"/testing", http.StatusUnauthorized, "baduser", "okpass"},
		{"/testing", http.StatusUnauthorized, "okuser", "badpass"},
		{"/testing", http.StatusUnauthorized, "OKuser", "okpass"},
		{"/testing", http.StatusUnauthorized, "OKuser", "badPASS"},
		{"/testing", http.StatusUnauthorized, "", "okpass"},
		{"/testing", http.StatusUnauthorized, "okuser", ""},
		{"/testing", http.StatusUnauthorized, "", ""},
	}

	//req, err := http.NewRequest("GET", test.from, nil)
	//req.Header.Add("Authorization", getDigestAuth(test.user, test.password, *res, test.from, "GET", nc))

	var test testType
	//nc := 1
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
			//var res http.Request

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
					if got, want := val[0], "Digest realm=\""+expectRealm+"\""; got != want {
						t.Errorf("Test %d: Www-Authenticate header should be '%s', got: '%s'", i, want, got)
					}
				} else {
					t.Errorf("Test %d: response should have a 'Www-Authenticate' header", i)
				}
			} else {
				if req.Header.Get("Authorization") == "" {
					// see issue #1508: https://github.com/mholt/caddy/issues/1508
					t.Errorf("Test %d: Expected Authorization header to be retained after successful auth, but was empty", i)
				}
			}
		}
	}
}

func TestMultipleOverlappingRules(t *testing.T) {
	rw := DigestAuth{
		Next: httpserver.HandlerFunc(contentHandler),
		Rules: []Rule{
			{Users: NewSimpleUserStore(map[string]string{"t": "p1"}),
				Resources: []string{"/t"}, Realm: "Restricted"},
			{Users: NewSimpleUserStore(map[string]string{"t1": "p2"}),
				Resources: []string{"/t/t"}, Realm: "Restricted"},
		},
	}
	rw.Rules[0].Digester = NewDigestHandler(rw.Rules[0].Realm, nil, nil, rw.Rules[0].Users)
	rw.Rules[1].Digester = NewDigestHandler(rw.Rules[1].Realm, nil, nil, rw.Rules[1].Users)

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
		auth := "Digest " + base64.StdEncoding.EncodeToString([]byte(test.cred))
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
	//htpasswdPasswd := "IedFOuGmTpT8"
	//htpasswdFile := `sha1:{SHA}dcAUljwz99qFjYR0YLTXx0RqLww=
	//md5:$apr1$l42y8rex$pOA2VJ0x/0TwaFeAF9nX61`

	//htfh, err := ioutil.TempFile("", "basicauth-")
	//if err != nil {
	//t.Skipf("Error creating temp file (%v), will skip htpassword test")
	//return
	//}
	//defer os.Remove(htfh.Name())
	//if _, err = htfh.Write([]byte(htpasswdFile)); err != nil {
	//t.Fatalf("write htpasswd file %q: %v", htfh.Name(), err)
	//}
	//htfh.Close()

	//for i, username := range []string{"sha1", "md5"} {
	//rule := Rule{Username: username, Resources: []string{"/testing"}}

	//siteRoot := filepath.Dir(htfh.Name())
	//filename := filepath.Base(htfh.Name())
	//if rule.Password, err = GetHtpasswdMatcher(filename, rule.Username, siteRoot); err != nil {
	//t.Fatalf("GetHtpasswdMatcher(%q, %q): %v", htfh.Name(), rule.Username, err)
	//}
	//t.Logf("%d. username=%q", i, rule.Username)
	//if !rule.Password(htpasswdPasswd) || rule.Password(htpasswdPasswd+"!") {
	//t.Errorf("%d (%s) password does not match.", i, rule.Username)
	//}
	//}
}

func getDigestAuth(username, password string, res *http.Response, url string, method string, nc int) string {
	var buf bytes.Buffer

	header := res.Header.Get("www-authenticate")
	parts := strings.SplitN(header, " ", 2)
	parts = strings.Split(parts[1], ", ")
	opts := make(map[string]string)

	for _, part := range parts {
		vals := strings.SplitN(part, "=", 2)
		key := vals[0]
		val := strings.Trim(vals[1], "\",")
		opts[key] = val
	}

	h := md5.New()
	fmt.Fprintf(&buf, "%s:%s:%s", username, opts["realm"], password)
	buf.WriteTo(h)
	ha1 := hex.EncodeToString(h.Sum(nil))

	h = md5.New()
	fmt.Fprintf(&buf, "%s:%s", method, url)
	buf.WriteTo(h)
	ha2 := hex.EncodeToString(h.Sum(nil))

	ncStr := fmt.Sprintf("%08x", nc)
	hnc := "MTM3MDgw"

	h = md5.New()
	fmt.Fprintf(&buf, "%s:%s:%s:%s:%s:%s", ha1, opts["nonce"], ncStr, hnc, opts["qop"], ha2)
	buf.WriteTo(h)
	respdig := hex.EncodeToString(h.Sum(nil))

	buf.Write([]byte("Digest "))
	fmt.Fprintf(&buf,
		`username="%s", realm="%s", nonce="%s", uri="%s", response="%s"`,
		username, opts["realm"], opts["nonce"], url, respdig,
	)

	if opts["opaque"] != "" {
		fmt.Fprintf(&buf, `, opaque="%s"`, opts["opaque"])
	}
	if opts["qop"] != "" {
		fmt.Fprintf(&buf, `, qop="%s", nc=%s, cnonce="%s"`, opts["qop"], ncStr, hnc)
	}
	if opts["algorithm"] != "" {
		fmt.Fprintf(&buf, `, algorithm="%s"`, opts["algorithm"])
	}

	return buf.String()
}
