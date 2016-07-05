package rewrite

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func TestRewrite(t *testing.T) {
	rw := Rewrite{
		Next: httpserver.HandlerFunc(urlPrinter),
		Rules: []Rule{
			NewSimpleRule("/from", "/to"),
			NewSimpleRule("/a", "/b"),
			NewSimpleRule("/b", "/b{uri}"),
		},
		FileSys: http.Dir("."),
	}

	regexps := [][]string{
		{"/reg/", ".*", "/to", ""},
		{"/r/", "[a-z]+", "/toaz", "!.html|"},
		{"/url/", "a([a-z0-9]*)s([A-Z]{2})", "/to/{path}", ""},
		{"/ab/", "ab", "/ab?{query}", ".txt|"},
		{"/ab/", "ab", "/ab?type=html&{query}", ".html|"},
		{"/abc/", "ab", "/abc/{file}", ".html|"},
		{"/abcd/", "ab", "/a/{dir}/{file}", ".html|"},
		{"/abcde/", "ab", "/a#{fragment}", ".html|"},
		{"/ab/", `.*\.jpg`, "/ajpg", ""},
		{"/reggrp", `/ad/([0-9]+)([a-z]*)`, "/a{1}/{2}", ""},
		{"/reg2grp", `(.*)`, "/{1}", ""},
		{"/reg3grp", `(.*)/(.*)/(.*)`, "/{1}{2}{3}", ""},
		{"/hashtest", "(.*)", "/{1}", ""},
	}

	for _, regexpRule := range regexps {
		var ext []string
		if s := strings.Split(regexpRule[3], "|"); len(s) > 1 {
			ext = s[:len(s)-1]
		}
		rule, err := NewComplexRule(regexpRule[0], regexpRule[1], regexpRule[2], 0, ext, httpserver.IfMatcher{})
		if err != nil {
			t.Fatal(err)
		}
		rw.Rules = append(rw.Rules, rule)
	}

	tests := []struct {
		from       string
		expectedTo string
	}{
		{"/from", "/to"},
		{"/a", "/b"},
		{"/b", "/b/b"},
		{"/aa", "/aa"},
		{"/", "/"},
		{"/a?foo=bar", "/b?foo=bar"},
		{"/asdf?foo=bar", "/asdf?foo=bar"},
		{"/foo#bar", "/foo#bar"},
		{"/a#foo", "/b#foo"},
		{"/reg/foo", "/to"},
		{"/re", "/re"},
		{"/r/", "/r/"},
		{"/r/123", "/r/123"},
		{"/r/a123", "/toaz"},
		{"/r/abcz", "/toaz"},
		{"/r/z", "/toaz"},
		{"/r/z.html", "/r/z.html"},
		{"/r/z.js", "/toaz"},
		{"/url/asAB", "/to/url/asAB"},
		{"/url/aBsAB", "/url/aBsAB"},
		{"/url/a00sAB", "/to/url/a00sAB"},
		{"/url/a0z0sAB", "/to/url/a0z0sAB"},
		{"/ab/aa", "/ab/aa"},
		{"/ab/ab", "/ab/ab"},
		{"/ab/ab.txt", "/ab"},
		{"/ab/ab.txt?name=name", "/ab?name=name"},
		{"/ab/ab.html?name=name", "/ab?type=html&name=name"},
		{"/abc/ab.html", "/abc/ab.html"},
		{"/abcd/abcd.html", "/a/abcd/abcd.html"},
		{"/abcde/abcde.html", "/a"},
		{"/abcde/abcde.html#1234", "/a#1234"},
		{"/ab/ab.jpg", "/ajpg"},
		{"/reggrp/ad/12", "/a12/"},
		{"/reggrp/ad/124a", "/a124/a"},
		{"/reggrp/ad/124abc", "/a124/abc"},
		{"/reg2grp/ad/124abc", "/ad/124abc"},
		{"/reg3grp/ad/aa/66", "/adaa66"},
		{"/reg3grp/ad612/n1n/ab", "/ad612n1nab"},
		{"/hashtest/a%20%23%20test", "/a%20%23%20test"},
		{"/hashtest/a%20%3F%20test", "/a%20%3F%20test"},
		{"/hashtest/a%20%3F%23test", "/a%20%3F%23test"},
	}

	for i, test := range tests {
		req, err := http.NewRequest("GET", test.from, nil)
		if err != nil {
			t.Fatalf("Test %d: Could not create HTTP request: %v", i, err)
		}

		rec := httptest.NewRecorder()
		rw.ServeHTTP(rec, req)

		if rec.Body.String() != test.expectedTo {
			t.Errorf("Test %d: Expected URL to be '%s' but was '%s'",
				i, test.expectedTo, rec.Body.String())
		}
	}

	statusTests := []struct {
		status         int
		base           string
		to             string
		regexp         string
		statusExpected bool
	}{
		{400, "/status", "", "", true},
		{400, "/ignore", "", "", false},
		{400, "/", "", "^/ignore", false},
		{400, "/", "", "(.*)", true},
		{400, "/status", "", "", true},
	}

	for i, s := range statusTests {
		urlPath := fmt.Sprintf("/status%d", i)
		rule, err := NewComplexRule(s.base, s.regexp, s.to, s.status, nil, httpserver.IfMatcher{})
		if err != nil {
			t.Fatalf("Test %d: No error expected for rule but found %v", i, err)
		}
		rw.Rules = []Rule{rule}
		req, err := http.NewRequest("GET", urlPath, nil)
		if err != nil {
			t.Fatalf("Test %d: Could not create HTTP request: %v", i, err)
		}

		rec := httptest.NewRecorder()
		code, err := rw.ServeHTTP(rec, req)
		if err != nil {
			t.Fatalf("Test %d: No error expected for handler but found %v", i, err)
		}
		if s.statusExpected {
			if rec.Body.String() != "" {
				t.Errorf("Test %d: Expected empty body but found %s", i, rec.Body.String())
			}
			if code != s.status {
				t.Errorf("Test %d: Expected status code %d found %d", i, s.status, code)
			}
		} else {
			if code != 0 {
				t.Errorf("Test %d: Expected no status code found %d", i, code)
			}
		}
	}
}

func urlPrinter(w http.ResponseWriter, r *http.Request) (int, error) {
	fmt.Fprint(w, r.URL.String())
	return 0, nil
}
