package parse

import (
	"os"
	"strings"
	"testing"
)

func TestStandardAddress(t *testing.T) {
	for i, test := range []struct {
		input              string
		scheme, host, port string
		shouldErr          bool
	}{
		{`localhost`, "", "localhost", "", false},
		{`localhost:1234`, "", "localhost", "1234", false},
		{`localhost:`, "", "localhost", "", false},
		{`0.0.0.0`, "", "0.0.0.0", "", false},
		{`127.0.0.1:1234`, "", "127.0.0.1", "1234", false},
		{`:1234`, "", "", "1234", false},
		{`[::1]`, "", "::1", "", false},
		{`[::1]:1234`, "", "::1", "1234", false},
		{`:`, "", "", "", false},
		{`localhost:http`, "http", "localhost", "80", false},
		{`localhost:https`, "https", "localhost", "443", false},
		{`:http`, "http", "", "80", false},
		{`:https`, "https", "", "443", false},
		{`http://localhost:https`, "", "", "", true}, // conflict
		{`http://localhost:http`, "", "", "", true},  // repeated scheme
		{`http://localhost:443`, "", "", "", true},   // not conventional
		{`https://localhost:80`, "", "", "", true},   // not conventional
		{`http://localhost`, "http", "localhost", "80", false},
		{`https://localhost`, "https", "localhost", "443", false},
		{`http://127.0.0.1`, "http", "127.0.0.1", "80", false},
		{`https://127.0.0.1`, "https", "127.0.0.1", "443", false},
		{`http://[::1]`, "http", "::1", "80", false},
		{`http://localhost:1234`, "http", "localhost", "1234", false},
		{`https://127.0.0.1:1234`, "https", "127.0.0.1", "1234", false},
		{`http://[::1]:1234`, "http", "::1", "1234", false},
		{``, "", "", "", false},
		{`::1`, "", "::1", "", true},
		{`localhost::`, "", "localhost::", "", true},
		{`#$%@`, "", "#$%@", "", true},
	} {
		actual, err := standardAddress(test.input)

		if err != nil && !test.shouldErr {
			t.Errorf("Test %d (%s): Expected no error, but had error: %v", i, test.input, err)
		}
		if err == nil && test.shouldErr {
			t.Errorf("Test %d (%s): Expected error, but had none", i, test.input)
		}

		if actual.Scheme != test.scheme {
			t.Errorf("Test %d (%s): Expected scheme '%s', got '%s'", i, test.input, test.scheme, actual.Scheme)
		}
		if actual.Host != test.host {
			t.Errorf("Test %d (%s): Expected host '%s', got '%s'", i, test.input, test.host, actual.Host)
		}
		if actual.Port != test.port {
			t.Errorf("Test %d (%s): Expected port '%s', got '%s'", i, test.input, test.port, actual.Port)
		}
	}
}

func TestParseOneAndImport(t *testing.T) {
	setupParseTests()

	testParseOne := func(input string) (ServerBlock, error) {
		p := testParser(input)
		p.Next() // parseOne doesn't call Next() to start, so we must
		err := p.parseOne()
		return p.block, err
	}

	for i, test := range []struct {
		input     string
		shouldErr bool
		addresses []address
		tokens    map[string]int // map of directive name to number of tokens expected
	}{
		{`localhost`, false, []address{
			{"localhost", "", "localhost", ""},
		}, map[string]int{}},

		{`localhost
		  dir1`, false, []address{
			{"localhost", "", "localhost", ""},
		}, map[string]int{
			"dir1": 1,
		}},

		{`localhost:1234
		  dir1 foo bar`, false, []address{
			{"localhost:1234", "", "localhost", "1234"},
		}, map[string]int{
			"dir1": 3,
		}},

		{`localhost {
		    dir1
		  }`, false, []address{
			{"localhost", "", "localhost", ""},
		}, map[string]int{
			"dir1": 1,
		}},

		{`localhost:1234 {
		    dir1 foo bar
		    dir2
		  }`, false, []address{
			{"localhost:1234", "", "localhost", "1234"},
		}, map[string]int{
			"dir1": 3,
			"dir2": 1,
		}},

		{`http://localhost https://localhost
		  dir1 foo bar`, false, []address{
			{"http://localhost", "http", "localhost", "80"},
			{"https://localhost", "https", "localhost", "443"},
		}, map[string]int{
			"dir1": 3,
		}},

		{`http://localhost https://localhost {
		    dir1 foo bar
		  }`, false, []address{
			{"http://localhost", "http", "localhost", "80"},
			{"https://localhost", "https", "localhost", "443"},
		}, map[string]int{
			"dir1": 3,
		}},

		{`http://localhost, https://localhost {
		    dir1 foo bar
		  }`, false, []address{
			{"http://localhost", "http", "localhost", "80"},
			{"https://localhost", "https", "localhost", "443"},
		}, map[string]int{
			"dir1": 3,
		}},

		{`http://localhost, {
		  }`, true, []address{
			{"http://localhost", "http", "localhost", "80"},
		}, map[string]int{}},

		{`host1:80, http://host2.com
		  dir1 foo bar
		  dir2 baz`, false, []address{
			{"host1:80", "", "host1", "80"},
			{"http://host2.com", "http", "host2.com", "80"},
		}, map[string]int{
			"dir1": 3,
			"dir2": 2,
		}},

		{`http://host1.com,
		  http://host2.com,
		  https://host3.com`, false, []address{
			{"http://host1.com", "http", "host1.com", "80"},
			{"http://host2.com", "http", "host2.com", "80"},
			{"https://host3.com", "https", "host3.com", "443"},
		}, map[string]int{}},

		{`http://host1.com:1234, https://host2.com
		  dir1 foo {
		    bar baz
		  }
		  dir2`, false, []address{
			{"http://host1.com:1234", "http", "host1.com", "1234"},
			{"https://host2.com", "https", "host2.com", "443"},
		}, map[string]int{
			"dir1": 6,
			"dir2": 1,
		}},

		{`127.0.0.1
		  dir1 {
		    bar baz
		  }
		  dir2 {
		    foo bar
		  }`, false, []address{
			{"127.0.0.1", "", "127.0.0.1", ""},
		}, map[string]int{
			"dir1": 5,
			"dir2": 5,
		}},

		{`127.0.0.1
		  unknown_directive`, true, []address{
			{"127.0.0.1", "", "127.0.0.1", ""},
		}, map[string]int{}},

		{`localhost
		  dir1 {
		    foo`, true, []address{
			{"localhost", "", "localhost", ""},
		}, map[string]int{
			"dir1": 3,
		}},

		{`localhost
		  dir1 {
		  }`, false, []address{
			{"localhost", "", "localhost", ""},
		}, map[string]int{
			"dir1": 3,
		}},

		{`localhost
		  dir1 {
		  } }`, true, []address{
			{"localhost", "", "localhost", ""},
		}, map[string]int{
			"dir1": 3,
		}},

		{`localhost
		  dir1 {
		    nested {
		      foo
		    }
		  }
		  dir2 foo bar`, false, []address{
			{"localhost", "", "localhost", ""},
		}, map[string]int{
			"dir1": 7,
			"dir2": 3,
		}},

		{``, false, []address{}, map[string]int{}},

		{`localhost
		  dir1 arg1
		  import import_test1.txt`, false, []address{
			{"localhost", "", "localhost", ""},
		}, map[string]int{
			"dir1": 2,
			"dir2": 3,
			"dir3": 1,
		}},

		{`import import_test2.txt`, false, []address{
			{"host1", "", "host1", ""},
		}, map[string]int{
			"dir1": 1,
			"dir2": 2,
		}},

		{`import import_test1.txt import_test2.txt`, true, []address{}, map[string]int{}},

		{`import not_found.txt`, true, []address{}, map[string]int{}},

		{`""`, false, []address{}, map[string]int{}},

		{``, false, []address{}, map[string]int{}},
	} {
		result, err := testParseOne(test.input)

		if test.shouldErr && err == nil {
			t.Errorf("Test %d: Expected an error, but didn't get one", i)
		}
		if !test.shouldErr && err != nil {
			t.Errorf("Test %d: Expected no error, but got: %v", i, err)
		}

		if len(result.Addresses) != len(test.addresses) {
			t.Errorf("Test %d: Expected %d addresses, got %d",
				i, len(test.addresses), len(result.Addresses))
			continue
		}
		for j, addr := range result.Addresses {
			if addr.Host != test.addresses[j].Host {
				t.Errorf("Test %d, address %d: Expected host to be '%s', but was '%s'",
					i, j, test.addresses[j].Host, addr.Host)
			}
			if addr.Port != test.addresses[j].Port {
				t.Errorf("Test %d, address %d: Expected port to be '%s', but was '%s'",
					i, j, test.addresses[j].Port, addr.Port)
			}
		}

		if len(result.Tokens) != len(test.tokens) {
			t.Errorf("Test %d: Expected %d directives, had %d",
				i, len(test.tokens), len(result.Tokens))
			continue
		}
		for directive, tokens := range result.Tokens {
			if len(tokens) != test.tokens[directive] {
				t.Errorf("Test %d, directive '%s': Expected %d tokens, counted %d",
					i, directive, test.tokens[directive], len(tokens))
				continue
			}
		}
	}
}

func TestParseAll(t *testing.T) {
	setupParseTests()

	for i, test := range []struct {
		input     string
		shouldErr bool
		addresses [][]address // addresses per server block, in order
	}{
		{`localhost`, false, [][]address{
			{{"localhost", "", "localhost", ""}},
		}},

		{`localhost:1234`, false, [][]address{
			{{"localhost:1234", "", "localhost", "1234"}},
		}},

		{`localhost:1234 {
		  }
		  localhost:2015 {
		  }`, false, [][]address{
			{{"localhost:1234", "", "localhost", "1234"}},
			{{"localhost:2015", "", "localhost", "2015"}},
		}},

		{`localhost:1234, http://host2`, false, [][]address{
			{{"localhost:1234", "", "localhost", "1234"}, {"http://host2", "http", "host2", "80"}},
		}},

		{`localhost:1234, http://host2,`, true, [][]address{}},

		{`http://host1.com, http://host2.com {
		  }
		  https://host3.com, https://host4.com {
		  }`, false, [][]address{
			{{"http://host1.com", "http", "host1.com", "80"}, {"http://host2.com", "http", "host2.com", "80"}},
			{{"https://host3.com", "https", "host3.com", "443"}, {"https://host4.com", "https", "host4.com", "443"}},
		}},

		{`import import_glob*.txt`, false, [][]address{
			{{"glob0.host0", "", "glob0.host0", ""}},
			{{"glob0.host1", "", "glob0.host1", ""}},
			{{"glob1.host0", "", "glob1.host0", ""}},
			{{"glob2.host0", "", "glob2.host0", ""}},
		}},
	} {
		p := testParser(test.input)
		blocks, err := p.parseAll()

		if test.shouldErr && err == nil {
			t.Errorf("Test %d: Expected an error, but didn't get one", i)
		}
		if !test.shouldErr && err != nil {
			t.Errorf("Test %d: Expected no error, but got: %v", i, err)
		}

		if len(blocks) != len(test.addresses) {
			t.Errorf("Test %d: Expected %d server blocks, got %d",
				i, len(test.addresses), len(blocks))
			continue
		}
		for j, block := range blocks {
			if len(block.Addresses) != len(test.addresses[j]) {
				t.Errorf("Test %d: Expected %d addresses in block %d, got %d",
					i, len(test.addresses[j]), j, len(block.Addresses))
				continue
			}
			for k, addr := range block.Addresses {
				if addr.Host != test.addresses[j][k].Host {
					t.Errorf("Test %d, block %d, address %d: Expected host to be '%s', but was '%s'",
						i, j, k, test.addresses[j][k].Host, addr.Host)
				}
				if addr.Port != test.addresses[j][k].Port {
					t.Errorf("Test %d, block %d, address %d: Expected port to be '%s', but was '%s'",
						i, j, k, test.addresses[j][k].Port, addr.Port)
				}
			}
		}
	}
}

func TestEnvironmentReplacement(t *testing.T) {
	setupParseTests()

	os.Setenv("PORT", "8080")
	os.Setenv("ADDRESS", "servername.com")
	os.Setenv("FOOBAR", "foobar")

	// basic test; unix-style env vars
	p := testParser(`{$ADDRESS}`)
	blocks, _ := p.parseAll()
	if actual, expected := blocks[0].Addresses[0].Host, "servername.com"; expected != actual {
		t.Errorf("Expected host to be '%s' but was '%s'", expected, actual)
	}

	// multiple vars per token
	p = testParser(`{$ADDRESS}:{$PORT}`)
	blocks, _ = p.parseAll()
	if actual, expected := blocks[0].Addresses[0].Host, "servername.com"; expected != actual {
		t.Errorf("Expected host to be '%s' but was '%s'", expected, actual)
	}
	if actual, expected := blocks[0].Addresses[0].Port, "8080"; expected != actual {
		t.Errorf("Expected port to be '%s' but was '%s'", expected, actual)
	}

	// windows-style var and unix style in same token
	p = testParser(`{%ADDRESS%}:{$PORT}`)
	blocks, _ = p.parseAll()
	if actual, expected := blocks[0].Addresses[0].Host, "servername.com"; expected != actual {
		t.Errorf("Expected host to be '%s' but was '%s'", expected, actual)
	}
	if actual, expected := blocks[0].Addresses[0].Port, "8080"; expected != actual {
		t.Errorf("Expected port to be '%s' but was '%s'", expected, actual)
	}

	// reverse order
	p = testParser(`{$ADDRESS}:{%PORT%}`)
	blocks, _ = p.parseAll()
	if actual, expected := blocks[0].Addresses[0].Host, "servername.com"; expected != actual {
		t.Errorf("Expected host to be '%s' but was '%s'", expected, actual)
	}
	if actual, expected := blocks[0].Addresses[0].Port, "8080"; expected != actual {
		t.Errorf("Expected port to be '%s' but was '%s'", expected, actual)
	}

	// env var in server block body as argument
	p = testParser(":{%PORT%}\ndir1 {$FOOBAR}")
	blocks, _ = p.parseAll()
	if actual, expected := blocks[0].Addresses[0].Port, "8080"; expected != actual {
		t.Errorf("Expected port to be '%s' but was '%s'", expected, actual)
	}
	if actual, expected := blocks[0].Tokens["dir1"][1].text, "foobar"; expected != actual {
		t.Errorf("Expected argument to be '%s' but was '%s'", expected, actual)
	}

	// combined windows env vars in argument
	p = testParser(":{%PORT%}\ndir1 {%ADDRESS%}/{%FOOBAR%}")
	blocks, _ = p.parseAll()
	if actual, expected := blocks[0].Tokens["dir1"][1].text, "servername.com/foobar"; expected != actual {
		t.Errorf("Expected argument to be '%s' but was '%s'", expected, actual)
	}

	// malformed env var (windows)
	p = testParser(":1234\ndir1 {%ADDRESS}")
	blocks, _ = p.parseAll()
	if actual, expected := blocks[0].Tokens["dir1"][1].text, "{%ADDRESS}"; expected != actual {
		t.Errorf("Expected host to be '%s' but was '%s'", expected, actual)
	}

	// malformed (non-existent) env var (unix)
	p = testParser(`:{$PORT$}`)
	blocks, _ = p.parseAll()
	if actual, expected := blocks[0].Addresses[0].Port, ""; expected != actual {
		t.Errorf("Expected port to be '%s' but was '%s'", expected, actual)
	}

	// in quoted field
	p = testParser(":1234\ndir1 \"Test {$FOOBAR} test\"")
	blocks, _ = p.parseAll()
	if actual, expected := blocks[0].Tokens["dir1"][1].text, "Test foobar test"; expected != actual {
		t.Errorf("Expected argument to be '%s' but was '%s'", expected, actual)
	}
}

func setupParseTests() {
	// Set up some bogus directives for testing
	ValidDirectives = map[string]struct{}{
		"dir1": {},
		"dir2": {},
		"dir3": {},
	}
}

func testParser(input string) parser {
	buf := strings.NewReader(input)
	p := parser{Dispenser: NewDispenser("Test", buf), checkDirectives: true}
	return p
}
