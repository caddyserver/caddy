package rewrite

import (
	"net/http"
	"net/url"
	"testing"
)

func TestTo(t *testing.T) {
	fs := http.Dir("testdata")
	tests := []struct {
		url      string
		to       string
		expected string
	}{
		{"/", "/somefiles", "/somefiles"},
		{"/somefiles", "/somefiles /index.php{uri}", "/index.php/somefiles"},
		{"/somefiles", "/testfile /index.php{uri}", "/testfile"},
		{"/somefiles", "/testfile/ /index.php{uri}", "/index.php/somefiles"},
		{"/somefiles", "/somefiles /index.php{uri}", "/index.php/somefiles"},
		{"/?a=b", "/somefiles /index.php?{query}", "/index.php?a=b"},
		{"/?a=b", "/testfile /index.php?{query}", "/testfile?a=b"},
		{"/?a=b", "/testdir /index.php?{query}", "/index.php?a=b"},
		{"/?a=b", "/testdir/ /index.php?{query}", "/testdir/?a=b"},
		{"/test?url=http://", " /p/{path}?{query}", "/p/test?url=http://"},
		{"/test?url=http://", " /p/{rewrite_path}?{query}", "/p/test?url=http://"},
		{"/test/?url=http://", " /{uri}", "/test/?url=http://"},
	}

	uri := func(r *url.URL) string {
		uri := r.Path
		if r.RawQuery != "" {
			uri += "?" + r.RawQuery
		}
		return uri
	}
	for i, test := range tests {
		r, err := http.NewRequest("GET", test.url, nil)
		if err != nil {
			t.Error(err)
		}
		To(fs, r, test.to, newReplacer(r))
		if uri(r.URL) != test.expected {
			t.Errorf("Test %v: expected %v found %v", i, test.expected, uri(r.URL))
		}
	}
}
