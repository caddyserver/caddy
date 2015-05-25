package rewrite

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"strings"

	"github.com/mholt/caddy/middleware"
)

func TestRewrite(t *testing.T) {
	rw := Rewrite{
		Next: middleware.HandlerFunc(urlPrinter),
		Rules: []Rule{
			NewSimpleRule("/from", "/to"),
			NewSimpleRule("/a", "/b"),
		},
	}

	regexpRules := [][]string{
		[]string{"/reg/", ".*", "/to", ""},
		[]string{"/r/", "[a-z]+", "/toaz", "!.html|"},
		[]string{"/url/", "a([a-z0-9]*)s([A-Z]{2})", "/to/{path}", ""},
		[]string{"/ab/", "ab", "/ab?{query}", ".txt|"},
		[]string{"/ab/", "ab", "/ab?type=html&{query}", ".html|"},
		[]string{"/abc/", "ab", "/abc/{file}", ".html|"},
		[]string{"/abcd/", "ab", "/a/{dir}/{file}", ".html|"},
		[]string{"/abcde/", "ab", "/a#{frag}", ".html|"},
		[]string{"/ab/", `.*\.jpg`, "/ajpg", ""},
	}

	for _, regexpRule := range regexpRules {
		var ext []string
		if s := strings.Split(regexpRule[3], "|"); len(s) > 1 {
			ext = s[:len(s)-1]
		}
		rule, err := NewRegexpRule(regexpRule[0], regexpRule[1], regexpRule[2], ext)
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
}

func urlPrinter(w http.ResponseWriter, r *http.Request) (int, error) {
	fmt.Fprintf(w, r.URL.String())
	return 0, nil
}
