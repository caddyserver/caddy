package gzip

import (
	"net/http"
	"testing"
)

func TestSet(t *testing.T) {
	set := make(Set)
	set.Add("a")
	if len(set) != 1 {
		t.Errorf("Expected 1 found %v", len(set))
	}
	set.Add("a")
	if len(set) != 1 {
		t.Errorf("Expected 1 found %v", len(set))
	}
	set.Add("b")
	if len(set) != 2 {
		t.Errorf("Expected 2 found %v", len(set))
	}
	if !set.Contains("a") {
		t.Errorf("Set should contain a")
	}
	if !set.Contains("b") {
		t.Errorf("Set should contain a")
	}
	set.Add("c")
	if len(set) != 3 {
		t.Errorf("Expected 3 found %v", len(set))
	}
	if !set.Contains("c") {
		t.Errorf("Set should contain c")
	}
	set.Remove("a")
	if len(set) != 2 {
		t.Errorf("Expected 2 found %v", len(set))
	}
	if set.Contains("a") {
		t.Errorf("Set should not contain a")
	}
	if !set.ContainsFunc(func(v string) bool {
		return v == "c"
	}) {
		t.Errorf("ContainsFunc should return true")
	}
}

func TestExtFilter(t *testing.T) {
	var filter Filter = ExtFilter{make(Set)}
	for _, e := range []string{".txt", ".html", ".css", ".md"} {
		filter.(ExtFilter).Exts.Add(e)
	}
	r := urlRequest("file.txt")
	if !filter.ShouldCompress(r) {
		t.Errorf("Should be valid filter")
	}
	var exts = []string{
		".html", ".css", ".md",
	}
	for i, e := range exts {
		r := urlRequest("file" + e)
		if !filter.ShouldCompress(r) {
			t.Errorf("Test %v: Should be valid filter", i)
		}
	}
	exts = []string{
		".htm1", ".abc", ".mdx",
	}
	for i, e := range exts {
		r := urlRequest("file" + e)
		if filter.ShouldCompress(r) {
			t.Errorf("Test %v: Should not be valid filter", i)
		}
	}
	filter.(ExtFilter).Exts.Add(ExtWildCard)
	for i, e := range exts {
		r := urlRequest("file" + e)
		if !filter.ShouldCompress(r) {
			t.Errorf("Test %v: Should be valid filter. Wildcard used.", i)
		}
	}
}

func TestPathFilter(t *testing.T) {
	paths := []string{
		"/a", "/b", "/c", "/de",
	}
	var filter Filter = PathFilter{make(Set)}
	for _, p := range paths {
		filter.(PathFilter).IgnoredPaths.Add(p)
	}
	for i, p := range paths {
		r := urlRequest(p)
		if filter.ShouldCompress(r) {
			t.Errorf("Test %v: Should not be valid filter", i)
		}
	}
	paths = []string{
		"/f", "/g", "/h", "/ed",
	}
	for i, p := range paths {
		r := urlRequest(p)
		if !filter.ShouldCompress(r) {
			t.Errorf("Test %v: Should be valid filter", i)
		}
	}
}

func urlRequest(url string) *http.Request {
	r, _ := http.NewRequest("GET", url, nil)
	return r
}
