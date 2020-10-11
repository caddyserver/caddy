package fileserver

import (
	"testing"
)

func TestBreadcrumbs(t *testing.T) {
	testdata := []struct {
		path     string
		expected []crumb
	}{
		{"", []crumb{}},
		{"/", []crumb{{Text: "/"}}},
		{"foo/bar/baz", []crumb{
			{Link: "../../", Text: "foo"},
			{Link: "../", Text: "bar"},
			{Link: "", Text: "baz"},
		}},
		{"/qux/quux/corge/", []crumb{
			{Link: "../../../", Text: "/"},
			{Link: "../../", Text: "qux"},
			{Link: "../", Text: "quux"},
			{Link: "", Text: "corge"},
		}},
	}

	for _, d := range testdata {
		l := browseListing{Path: d.path}
		actual := l.Breadcrumbs()
		if len(actual) != len(d.expected) {
			t.Errorf("wrong size output, got %d elements but expected %d", len(actual), len(d.expected))
			continue
		}
		for i, c := range actual {
			if c != d.expected[i] {
				t.Errorf("got %#v but expected %#v at index %d", c, d.expected[i], i)
			}
		}
	}
}
