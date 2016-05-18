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
		{"not-in-trie.com", false, ""},
		{"example", true, "example"},
		{"example.com", true, "example.com"},
		{"example.com/test", true, "example.com"},
		{"example.com/foo", true, "example.com/foo"},
		{"example.com/foo/", true, "example.com/foo"},
		{"example.com/foo/bar", true, "example.com/foo/bar"},
		{"example.com/foo/bar/baz", true, "example.com/foo/bar"},
		{"example.com/foo/other", true, "example.com/foo"},
		{"foo.example.com", true, "*.example.com"},
		{"foo.example.com/else", true, "*.example.com"},
	}, false)

	// Try again with wildcard hosts
	trie = newVHostTrie()
	populateTestTrie(trie, []string{
		"example.com",
		"",
	})
	assertTestTrie(t, trie, []vhostTrieTest{
		{"not-in-trie.com", true, ""},
		{"example.com", true, "example.com"},
		{"example.com/foo", true, "example.com"},
		{"not-in-trie.com/asdf", true, ""},
	}, true)

	trie = newVHostTrie()
	populateTestTrie(trie, []string{
		"0.0.0.0/asdf",
	})
	assertTestTrie(t, trie, []vhostTrieTest{
		{"example.com/asdf/foo", true, "0.0.0.0/asdf"},
		{"example.com/foo", false, ""},
		{"host/asdf", true, "0.0.0.0/asdf"},
	}, true)

	trie = newVHostTrie()
	populateTestTrie(trie, []string{
		"*/foo",
	})
	assertTestTrie(t, trie, []vhostTrieTest{
		{"example.com/foo", true, "*/foo"},
		{"example.com", false, ""},
	}, true)

	// Make sure port is stripped out
	trie = newVHostTrie()
	populateTestTrie(trie, []string{
		"example.com:1234",
	})
	assertTestTrie(t, trie, []vhostTrieTest{
		{"example.com/foo", true, "example.com:1234"},
	}, true)
}

func populateTestTrie(trie *vhostTrie, keys []string) {
	for _, key := range keys {
		// we wrap this in a func, passing in the key, otherwise the
		// handler always writes the last key to the response, even
		// if the handler is actually from one of the earlier keys.
		func(key string) {
			trie.Insert(key, HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) {
				w.Write([]byte(key))
				return 0, nil
			}))
		}(key)
	}
}

type vhostTrieTest struct {
	query         string
	expectHandler bool
	expectedKey   string
}

func assertTestTrie(t *testing.T, trie *vhostTrie, tests []vhostTrieTest, hasWildcardHosts bool) {
	for i, test := range tests {
		stack := trie.Match(test.query)

		if !test.expectHandler {
			if stack != nil {
				// If not expecting a value, then just make sure we didn't get one
				t.Errorf("Test %d: Expected no matches, but got %v", i, stack)
			}
			continue
		}

		// Otherwise, we must assert we got a value
		if stack == nil {
			t.Errorf("Test %d: Expected non-nil middleware stack, but got: %v", i, stack)
			continue
		}

		// And it must be the correct value
		resp := httptest.NewRecorder()
		stack.ServeHTTP(resp, nil)
		actualHandlerKey := resp.Body.String()
		if actualHandlerKey != test.expectedKey {
			t.Errorf("Test %d: Expected match '%s' but matched '%s'",
				i, test.expectedKey, actualHandlerKey)
		}
	}
}
