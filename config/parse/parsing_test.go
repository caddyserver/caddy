package parse

import (
	"strings"
	"testing"
)

func TestStandardAddress(t *testing.T) {
	for i, test := range []struct {
		input      string
		host, port string
		shouldErr  bool
	}{
		{`localhost`, "localhost", "", false},
		{`localhost:1234`, "localhost", "1234", false},
		{`localhost:`, "localhost", "", false},
		{`0.0.0.0`, "0.0.0.0", "", false},
		{`127.0.0.1:1234`, "127.0.0.1", "1234", false},
		{`:1234`, "", "1234", false},
		{`[::1]`, "::1", "", false},
		{`[::1]:1234`, "::1", "1234", false},
		{`:`, "", "", false},
		{`localhost:http`, "localhost", "http", false},
		{`localhost:https`, "localhost", "https", false},
		{`:http`, "", "http", false},
		{`:https`, "", "https", false},
		{`http://localhost`, "localhost", "http", false},
		{`https://localhost`, "localhost", "https", false},
		{`http://127.0.0.1`, "127.0.0.1", "http", false},
		{`https://127.0.0.1`, "127.0.0.1", "https", false},
		{`http://[::1]`, "::1", "http", false},
		{`http://localhost:1234`, "localhost", "1234", false},
		{`https://127.0.0.1:1234`, "127.0.0.1", "1234", false},
		{`http://[::1]:1234`, "::1", "1234", false},
		{``, "", "", false},
		{`::1`, "::1", "", true},
		{`localhost::`, "localhost::", "", true},
		{`#$%@`, "#$%@", "", true},
	} {
		host, port, err := standardAddress(test.input)

		if err != nil && !test.shouldErr {
			t.Errorf("Test %d: Expected no error, but had error: %v", i, err)
		}
		if err == nil && test.shouldErr {
			t.Errorf("Test %d: Expected error, but had none", i)
		}

		if host != test.host {
			t.Errorf("Test %d: Expected host '%s', got '%s'", i, test.host, host)
		}

		if port != test.port {
			t.Errorf("Test %d: Expected port '%s', got '%s'", i, test.port, port)
		}
	}
}

func TestParseOneAndImport(t *testing.T) {
	setupParseTests()

	testParseOne := func(input string) (serverBlock, error) {
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
			{"localhost", ""},
		}, map[string]int{}},

		{`localhost
		  dir1`, false, []address{
			{"localhost", ""},
		}, map[string]int{
			"dir1": 1,
		}},

		{`localhost:1234
		  dir1 foo bar`, false, []address{
			{"localhost", "1234"},
		}, map[string]int{
			"dir1": 3,
		}},

		{`localhost {
		    dir1
		  }`, false, []address{
			{"localhost", ""},
		}, map[string]int{
			"dir1": 1,
		}},

		{`localhost:1234 {
		    dir1 foo bar
		    dir2
		  }`, false, []address{
			{"localhost", "1234"},
		}, map[string]int{
			"dir1": 3,
			"dir2": 1,
		}},

		{`http://localhost https://localhost
		  dir1 foo bar`, false, []address{
			{"localhost", "http"},
			{"localhost", "https"},
		}, map[string]int{
			"dir1": 3,
		}},

		{`http://localhost https://localhost {
		    dir1 foo bar
		  }`, false, []address{
			{"localhost", "http"},
			{"localhost", "https"},
		}, map[string]int{
			"dir1": 3,
		}},

		{`http://localhost, https://localhost {
		    dir1 foo bar
		  }`, false, []address{
			{"localhost", "http"},
			{"localhost", "https"},
		}, map[string]int{
			"dir1": 3,
		}},

		{`http://localhost, {
		  }`, true, []address{
			{"localhost", "http"},
		}, map[string]int{}},

		{`host1:80, http://host2.com
		  dir1 foo bar
		  dir2 baz`, false, []address{
			{"host1", "80"},
			{"host2.com", "http"},
		}, map[string]int{
			"dir1": 3,
			"dir2": 2,
		}},

		{`http://host1.com,
		  http://host2.com,
		  https://host3.com`, false, []address{
			{"host1.com", "http"},
			{"host2.com", "http"},
			{"host3.com", "https"},
		}, map[string]int{}},

		{`http://host1.com:1234, https://host2.com
		  dir1 foo {
		    bar baz
		  }
		  dir2`, false, []address{
			{"host1.com", "1234"},
			{"host2.com", "https"},
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
			{"127.0.0.1", ""},
		}, map[string]int{
			"dir1": 5,
			"dir2": 5,
		}},

		{`127.0.0.1
		  unknown_directive`, true, []address{
			{"127.0.0.1", ""},
		}, map[string]int{}},

		{`localhost
		  dir1 {
		    foo`, true, []address{
			{"localhost", ""},
		}, map[string]int{
			"dir1": 3,
		}},

		{`localhost
		  dir1 {
		  }`, false, []address{
			{"localhost", ""},
		}, map[string]int{
			"dir1": 3,
		}},

		{`localhost
		  dir1 {
		  } }`, true, []address{
			{"localhost", ""},
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
			{"localhost", ""},
		}, map[string]int{
			"dir1": 7,
			"dir2": 3,
		}},

		{``, false, []address{}, map[string]int{}},

		{`localhost
		  dir1 arg1
		  import import_test1.txt`, false, []address{
			{"localhost", ""},
		}, map[string]int{
			"dir1": 2,
			"dir2": 3,
			"dir3": 1,
		}},

		{`import import_test2.txt`, false, []address{
			{"host1", ""},
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
			{{"localhost", ""}},
		}},

		{`localhost:1234`, false, [][]address{
			[]address{{"localhost", "1234"}},
		}},

		{`localhost:1234 {
		  }
		  localhost:2015 {
		  }`, false, [][]address{
			[]address{{"localhost", "1234"}},
			[]address{{"localhost", "2015"}},
		}},

		{`localhost:1234, http://host2`, false, [][]address{
			[]address{{"localhost", "1234"}, {"host2", "http"}},
		}},

		{`localhost:1234, http://host2,`, true, [][]address{}},

		{`http://host1.com, http://host2.com {
		  }
		  https://host3.com, https://host4.com {
		  }`, false, [][]address{
			[]address{{"host1.com", "http"}, {"host2.com", "http"}},
			[]address{{"host3.com", "https"}, {"host4.com", "https"}},
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
	p := parser{Dispenser: NewDispenser("Test", buf)}
	return p
}
