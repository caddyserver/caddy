package httpserver

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVHostTrie(t *testing.T) {
	trie := newVHostTrie()
	populateTestTrie(trie, []string{
		"example",
		"example.com",
		"*.example.com",
		"example.com/foo",
		"example.com/foo/bar",
		"*.example.com/test",
	})
	assertTestTrie(t, trie, []vhostTrieTest{
		{"not-in-trie.com", false, "", "/"},
		{"example", true, "example", "/"},
		{"example.com", true, "example.com", "/"},
		{"example.com/test", true, "example.com", "/"},
		{"example.com/foo", true, "example.com/foo", "/foo"},
		{"example.com/foo/", true, "example.com/foo", "/foo"},
		{"EXAMPLE.COM/foo", true, "example.com/foo", "/foo"},
		{"EXAMPLE.COM/Foo", true, "example.com", "/"},
		{"example.com/foo/bar", true, "example.com/foo/bar", "/foo/bar"},
		{"example.com/foo/bar/baz", true, "example.com/foo/bar", "/foo/bar"},
		{"example.com/foo/other", true, "example.com/foo", "/foo"},
		{"foo.example.com", true, "*.example.com", "/"},
		{"foo.example.com/else", true, "*.example.com", "/"},
	}, false)
}

func TestVHostTrieWildcard1(t *testing.T) {
	trie := newVHostTrie()
	populateTestTrie(trie, []string{
		"example.com",
		"",
	})
	assertTestTrie(t, trie, []vhostTrieTest{
		{"not-in-trie.com", true, "", "/"},
		{"example.com", true, "example.com", "/"},
		{"example.com/foo", true, "example.com", "/"},
		{"not-in-trie.com/asdf", true, "", "/"},
	}, true)
}

func TestVHostTrieWildcard2(t *testing.T) {
	trie := newVHostTrie()
	populateTestTrie(trie, []string{
		"0.0.0.0/asdf",
	})
	assertTestTrie(t, trie, []vhostTrieTest{
		{"example.com/asdf/foo", true, "0.0.0.0/asdf", "/asdf"},
		{"example.com/foo", false, "", "/"},
		{"host/asdf", true, "0.0.0.0/asdf", "/asdf"},
	}, true)
}

func TestVHostTrieWildcard3(t *testing.T) {
	trie := newVHostTrie()
	populateTestTrie(trie, []string{
		"*/foo",
	})
	assertTestTrie(t, trie, []vhostTrieTest{
		{"example.com/foo", true, "*/foo", "/foo"},
		{"example.com", false, "", "/"},
	}, true)
}

func TestVHostTriePort(t *testing.T) {
	// Make sure port is stripped out
	trie := newVHostTrie()
	populateTestTrie(trie, []string{
		"example.com:1234",
	})
	assertTestTrie(t, trie, []vhostTrieTest{
		{"example.com/foo", true, "example.com:1234", "/"},
	}, true)
}

func populateTestTrie(trie *vhostTrie, keys []string) {
	for _, key := range keys {
		// we wrap this in a func, passing in the key, otherwise the
		// handler always writes the last key to the response, even
		// if the handler is actually from one of the earlier keys.
		func(key string) {
			site := &SiteConfig{
				middlewareChain: HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) {
					w.Write([]byte(key))
					return 0, nil
				}),
			}
			trie.Insert(key, site)
		}(key)
	}
}

type vhostTrieTest struct {
	query         string
	expectMatch   bool
	expectedKey   string
	matchedPrefix string // the path portion of a key that is expected to be matched
}

func assertTestTrie(t *testing.T, trie *vhostTrie, tests []vhostTrieTest, hasWildcardHosts bool) {
	for i, test := range tests {
		site, pathPrefix := trie.Match(test.query)

		if !test.expectMatch {
			if site != nil {
				// If not expecting a value, then just make sure we didn't get one
				t.Errorf("Test %d: Expected no matches, but got %v", i, site)
			}
			continue
		}

		// Otherwise, we must assert we got a value
		if site == nil {
			t.Errorf("Test %d: Expected non-nil return value, but got: %v", i, site)
			continue
		}

		// And it must be the correct value
		resp := httptest.NewRecorder()
		site.middlewareChain.ServeHTTP(resp, nil)
		actualHandlerKey := resp.Body.String()
		if actualHandlerKey != test.expectedKey {
			t.Errorf("Test %d: Expected match '%s' but matched '%s'",
				i, test.expectedKey, actualHandlerKey)
		}

		// The path prefix must also be correct
		if test.matchedPrefix != pathPrefix {
			t.Errorf("Test %d: Expected matched path prefix to be '%s', got '%s'",
				i, test.matchedPrefix, pathPrefix)
		}
	}
}
