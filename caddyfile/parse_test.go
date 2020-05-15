// Copyright 2015 Light Code Labs, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package caddyfile

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAllTokens(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "not-empty",
			input:    "a b c\nd e",
			expected: []string{"a", "b", "c", "d", "e"},
		}, {
			name:  "empty",
			input: "",
		}, {
			name:  "newline",
			input: "\n",
		}, {
			name:  "space",
			input: " ",
		}, {
			name:  "tab and newline",
			input: "\t\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens, err := allTokens(strings.NewReader(tt.input))

			if err != nil {
				t.Fatalf("Expected no error, got %v", err)
			}
			if len(tokens) != len(tt.expected) {
				t.Fatalf("Expected %d tokens, got %d", len(tt.expected), len(tokens))
			}

			for i, val := range tt.expected {
				if tokens[i].Text != val {
					t.Errorf("Token %d should be '%s' but was '%s'", i, val, tokens[i].Text)
				}
			}
		})
	}
}

func TestParseOneAndImport(t *testing.T) {
	testParseOne := func(input string) (ServerBlock, error) {
		p := testParser(input)
		p.Next() // parseOne doesn't call Next() to start, so we must
		err := p.parseOne()
		return p.block, err
	}

	for i, test := range []struct {
		input     string
		shouldErr bool
		keys      []string
		tokens    map[string]int // map of directive name to number of tokens expected
	}{
		{`localhost`, false, []string{
			"localhost",
		}, map[string]int{}},

		{`localhost
		  dir1`, false, []string{
			"localhost",
		}, map[string]int{
			"dir1": 1,
		}},

		{`localhost:1234
		  dir1 foo bar`, false, []string{
			"localhost:1234",
		}, map[string]int{
			"dir1": 3,
		}},

		{`localhost {
		    dir1
		  }`, false, []string{
			"localhost",
		}, map[string]int{
			"dir1": 1,
		}},

		{`localhost:1234 {
		    dir1 foo bar
		    dir2
		  }`, false, []string{
			"localhost:1234",
		}, map[string]int{
			"dir1": 3,
			"dir2": 1,
		}},

		{`http://localhost https://localhost
		  dir1 foo bar`, false, []string{
			"http://localhost",
			"https://localhost",
		}, map[string]int{
			"dir1": 3,
		}},

		{`http://localhost https://localhost {
		    dir1 foo bar
		  }`, false, []string{
			"http://localhost",
			"https://localhost",
		}, map[string]int{
			"dir1": 3,
		}},

		{`http://localhost, https://localhost {
		    dir1 foo bar
		  }`, false, []string{
			"http://localhost",
			"https://localhost",
		}, map[string]int{
			"dir1": 3,
		}},

		{`http://localhost, {
		  }`, true, []string{
			"http://localhost",
		}, map[string]int{}},

		{`host1:80, http://host2.com
		  dir1 foo bar
		  dir2 baz`, false, []string{
			"host1:80",
			"http://host2.com",
		}, map[string]int{
			"dir1": 3,
			"dir2": 2,
		}},

		{`http://host1.com,
		  http://host2.com,
		  https://host3.com`, false, []string{
			"http://host1.com",
			"http://host2.com",
			"https://host3.com",
		}, map[string]int{}},

		{`http://host1.com:1234, https://host2.com
		  dir1 foo {
		    bar baz
		  }
		  dir2`, false, []string{
			"http://host1.com:1234",
			"https://host2.com",
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
		  }`, false, []string{
			"127.0.0.1",
		}, map[string]int{
			"dir1": 5,
			"dir2": 5,
		}},

		{`localhost
		  dir1 {
		    foo`, true, []string{
			"localhost",
		}, map[string]int{
			"dir1": 3,
		}},

		{`localhost
		  dir1 {
		  }`, false, []string{
			"localhost",
		}, map[string]int{
			"dir1": 3,
		}},

		{`localhost
		  dir1 {
		  } }`, true, []string{
			"localhost",
		}, map[string]int{
			"dir1": 3,
		}},

		{`localhost
		  dir1 {
		    nested {
		      foo
		    }
		  }
		  dir2 foo bar`, false, []string{
			"localhost",
		}, map[string]int{
			"dir1": 7,
			"dir2": 3,
		}},

		{``, false, []string{}, map[string]int{}},

		{`localhost
		  dir1 arg1
		  import testdata/import_test1.txt`, false, []string{
			"localhost",
		}, map[string]int{
			"dir1": 2,
			"dir2": 3,
			"dir3": 1,
		}},

		{`import testdata/import_test2.txt`, false, []string{
			"host1",
		}, map[string]int{
			"dir1": 1,
			"dir2": 2,
		}},

		{`import testdata/import_test1.txt testdata/import_test2.txt`, true, []string{}, map[string]int{}},

		{`import testdata/not_found.txt`, true, []string{}, map[string]int{}},

		{`""`, false, []string{}, map[string]int{}},

		{``, false, []string{}, map[string]int{}},

		// test cases found by fuzzing!
		{`import }{$"`, true, []string{}, map[string]int{}},
		{`import /*/*.txt`, true, []string{}, map[string]int{}},
		{`import /???/?*?o`, true, []string{}, map[string]int{}},
		{`import /??`, true, []string{}, map[string]int{}},
		{`import /[a-z]`, true, []string{}, map[string]int{}},
		{`import {$}`, true, []string{}, map[string]int{}},
		{`import {%}`, true, []string{}, map[string]int{}},
		{`import {$$}`, true, []string{}, map[string]int{}},
		{`import {%%}`, true, []string{}, map[string]int{}},
	} {
		result, err := testParseOne(test.input)

		if test.shouldErr && err == nil {
			t.Errorf("Test %d: Expected an error, but didn't get one", i)
		}
		if !test.shouldErr && err != nil {
			t.Errorf("Test %d: Expected no error, but got: %v", i, err)
		}

		if len(result.Keys) != len(test.keys) {
			t.Errorf("Test %d: Expected %d keys, got %d",
				i, len(test.keys), len(result.Keys))
			continue
		}
		for j, addr := range result.Keys {
			if addr != test.keys[j] {
				t.Errorf("Test %d, key %d: Expected '%s', but was '%s'",
					i, j, test.keys[j], addr)
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

func TestRecursiveImport(t *testing.T) {
	testParseOne := func(input string) (ServerBlock, error) {
		p := testParser(input)
		p.Next() // parseOne doesn't call Next() to start, so we must
		err := p.parseOne()
		return p.block, err
	}

	isExpected := func(got ServerBlock) bool {
		if len(got.Keys) != 1 || got.Keys[0] != "localhost" {
			t.Errorf("got keys unexpected: expect localhost, got %v", got.Keys)
			return false
		}
		if len(got.Tokens) != 2 {
			t.Errorf("got wrong number of tokens: expect 2, got %d", len(got.Tokens))
			return false
		}
		if len(got.Tokens["dir1"]) != 1 || len(got.Tokens["dir2"]) != 2 {
			t.Errorf("got unexpect tokens: %v", got.Tokens)
			return false
		}
		return true
	}

	recursiveFile1, err := filepath.Abs("testdata/recursive_import_test1")
	if err != nil {
		t.Fatal(err)
	}
	recursiveFile2, err := filepath.Abs("testdata/recursive_import_test2")
	if err != nil {
		t.Fatal(err)
	}

	// test relative recursive import
	err = ioutil.WriteFile(recursiveFile1, []byte(
		`localhost
		dir1
		import recursive_import_test2`), 0644)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(recursiveFile1)

	err = ioutil.WriteFile(recursiveFile2, []byte("dir2 1"), 0644)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(recursiveFile2)

	// import absolute path
	result, err := testParseOne("import " + recursiveFile1)
	if err != nil {
		t.Fatal(err)
	}
	if !isExpected(result) {
		t.Error("absolute+relative import failed")
	}

	// import relative path
	result, err = testParseOne("import testdata/recursive_import_test1")
	if err != nil {
		t.Fatal(err)
	}
	if !isExpected(result) {
		t.Error("relative+relative import failed")
	}

	// test absolute recursive import
	err = ioutil.WriteFile(recursiveFile1, []byte(
		`localhost
		dir1
		import `+recursiveFile2), 0644)
	if err != nil {
		t.Fatal(err)
	}

	// import absolute path
	result, err = testParseOne("import " + recursiveFile1)
	if err != nil {
		t.Fatal(err)
	}
	if !isExpected(result) {
		t.Error("absolute+absolute import failed")
	}

	// import relative path
	result, err = testParseOne("import testdata/recursive_import_test1")
	if err != nil {
		t.Fatal(err)
	}
	if !isExpected(result) {
		t.Error("relative+absolute import failed")
	}
}

func TestDirectiveImport(t *testing.T) {
	testParseOne := func(input string) (ServerBlock, error) {
		p := testParser(input)
		p.Next() // parseOne doesn't call Next() to start, so we must
		err := p.parseOne()
		return p.block, err
	}

	isExpected := func(got ServerBlock) bool {
		if len(got.Keys) != 1 || got.Keys[0] != "localhost" {
			t.Errorf("got keys unexpected: expect localhost, got %v", got.Keys)
			return false
		}
		if len(got.Tokens) != 2 {
			t.Errorf("got wrong number of tokens: expect 2, got %d", len(got.Tokens))
			return false
		}
		if len(got.Tokens["dir1"]) != 1 || len(got.Tokens["proxy"]) != 8 {
			t.Errorf("got unexpect tokens: %v", got.Tokens)
			return false
		}
		return true
	}

	directiveFile, err := filepath.Abs("testdata/directive_import_test")
	if err != nil {
		t.Fatal(err)
	}

	err = ioutil.WriteFile(directiveFile, []byte(`prop1 1
	prop2 2`), 0644)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(directiveFile)

	// import from existing file
	result, err := testParseOne(`localhost
	dir1
	proxy {
		import testdata/directive_import_test
		transparent
	}`)
	if err != nil {
		t.Fatal(err)
	}
	if !isExpected(result) {
		t.Error("directive import failed")
	}

	// import from nonexistent file
	_, err = testParseOne(`localhost
	dir1
	proxy {
		import testdata/nonexistent_file
		transparent
	}`)
	if err == nil {
		t.Fatal("expected error when importing a nonexistent file")
	}
}

func TestParseAll(t *testing.T) {
	for i, test := range []struct {
		input     string
		shouldErr bool
		keys      [][]string // keys per server block, in order
	}{
		{`localhost`, false, [][]string{
			{"localhost"},
		}},

		{`localhost:1234`, false, [][]string{
			{"localhost:1234"},
		}},

		{`localhost:1234 {
		  }
		  localhost:2015 {
		  }`, false, [][]string{
			{"localhost:1234"},
			{"localhost:2015"},
		}},

		{`localhost:1234, http://host2`, false, [][]string{
			{"localhost:1234", "http://host2"},
		}},

		{`localhost:1234, http://host2,`, true, [][]string{}},

		{`http://host1.com, http://host2.com {
		  }
		  https://host3.com, https://host4.com {
		  }`, false, [][]string{
			{"http://host1.com", "http://host2.com"},
			{"https://host3.com", "https://host4.com"},
		}},

		{`import testdata/import_glob*.txt`, false, [][]string{
			{"glob0.host0"},
			{"glob0.host1"},
			{"glob1.host0"},
			{"glob2.host0"},
		}},

		{`import notfound/*`, false, [][]string{}},        // glob needn't error with no matches
		{`import notfound/file.conf`, true, [][]string{}}, // but a specific file should
	} {
		p := testParser(test.input)
		blocks, err := p.parseAll()

		if test.shouldErr && err == nil {
			t.Errorf("Test %d: Expected an error, but didn't get one", i)
		}
		if !test.shouldErr && err != nil {
			t.Errorf("Test %d: Expected no error, but got: %v", i, err)
		}

		if len(blocks) != len(test.keys) {
			t.Errorf("Test %d: Expected %d server blocks, got %d",
				i, len(test.keys), len(blocks))
			continue
		}
		for j, block := range blocks {
			if len(block.Keys) != len(test.keys[j]) {
				t.Errorf("Test %d: Expected %d keys in block %d, got %d",
					i, len(test.keys[j]), j, len(block.Keys))
				continue
			}
			for k, addr := range block.Keys {
				if addr != test.keys[j][k] {
					t.Errorf("Test %d, block %d, key %d: Expected '%s', but got '%s'",
						i, j, k, test.keys[j][k], addr)
				}
			}
		}
	}
}

func TestEnvironmentReplacement(t *testing.T) {
	os.Setenv("PORT", "8080")
	os.Setenv("ADDRESS", "servername.com")
	os.Setenv("FOOBAR", "foobar")
	os.Setenv("PARTIAL_DIR", "r1")

	// basic test; unix-style env vars
	p := testParser(`{$ADDRESS}`)
	blocks, _ := p.parseAll()
	if actual, expected := blocks[0].Keys[0], "servername.com"; expected != actual {
		t.Errorf("Expected key to be '%s' but was '%s'", expected, actual)
	}

	// basic test; unix-style env vars
	p = testParser(`di{$PARTIAL_DIR}`)
	blocks, _ = p.parseAll()
	if actual, expected := blocks[0].Keys[0], "dir1"; expected != actual {
		t.Errorf("Expected key to be '%s' but was '%s'", expected, actual)
	}

	// multiple vars per token
	p = testParser(`{$ADDRESS}:{$PORT}`)
	blocks, _ = p.parseAll()
	if actual, expected := blocks[0].Keys[0], "servername.com:8080"; expected != actual {
		t.Errorf("Expected key to be '%s' but was '%s'", expected, actual)
	}

	// windows-style var and unix style in same token
	p = testParser(`{%ADDRESS%}:{$PORT}`)
	blocks, _ = p.parseAll()
	if actual, expected := blocks[0].Keys[0], "servername.com:8080"; expected != actual {
		t.Errorf("Expected key to be '%s' but was '%s'", expected, actual)
	}

	// reverse order
	p = testParser(`{$ADDRESS}:{%PORT%}`)
	blocks, _ = p.parseAll()
	if actual, expected := blocks[0].Keys[0], "servername.com:8080"; expected != actual {
		t.Errorf("Expected key to be '%s' but was '%s'", expected, actual)
	}

	// env var in server block body as argument
	p = testParser(":{%PORT%}\ndir1 {$FOOBAR}")
	blocks, _ = p.parseAll()
	if actual, expected := blocks[0].Keys[0], ":8080"; expected != actual {
		t.Errorf("Expected key to be '%s' but was '%s'", expected, actual)
	}
	if actual, expected := blocks[0].Tokens["dir1"][1].Text, "foobar"; expected != actual {
		t.Errorf("Expected argument to be '%s' but was '%s'", expected, actual)
	}

	// combined windows env vars in argument
	p = testParser(":{%PORT%}\ndir1 {%ADDRESS%}/{%FOOBAR%}")
	blocks, _ = p.parseAll()
	if actual, expected := blocks[0].Tokens["dir1"][1].Text, "servername.com/foobar"; expected != actual {
		t.Errorf("Expected argument to be '%s' but was '%s'", expected, actual)
	}

	// malformed env var (windows)
	p = testParser(":1234\ndir1 {%ADDRESS}")
	blocks, _ = p.parseAll()
	if actual, expected := blocks[0].Tokens["dir1"][1].Text, "{%ADDRESS}"; expected != actual {
		t.Errorf("Expected host to be '%s' but was '%s'", expected, actual)
	}

	// malformed (non-existent) env var (unix)
	p = testParser(`:{$PORT$}`)
	blocks, _ = p.parseAll()
	if actual, expected := blocks[0].Keys[0], ":"; expected != actual {
		t.Errorf("Expected key to be '%s' but was '%s'", expected, actual)
	}

	// in quoted field
	p = testParser(":1234\ndir1 \"Test {$FOOBAR} test\"")
	blocks, _ = p.parseAll()
	if actual, expected := blocks[0].Tokens["dir1"][1].Text, "Test foobar test"; expected != actual {
		t.Errorf("Expected argument to be '%s' but was '%s'", expected, actual)
	}

	// after end token
	p = testParser(":1234\nanswer \"{{ .Name }} {$FOOBAR}\"")
	blocks, _ = p.parseAll()
	if actual, expected := blocks[0].Tokens["answer"][1].Text, "{{ .Name }} foobar"; expected != actual {
		t.Errorf("Expected argument to be '%s' but was '%s'", expected, actual)
	}
}

func testParser(input string) parser {
	buf := strings.NewReader(input)
	p := parser{Dispenser: NewDispenser("Caddyfile", buf)}
	return p
}

func TestSnippets(t *testing.T) {
	p := testParser(`
		(common) {
			gzip foo
			errors stderr
		}
		http://example.com {
			import common
		}
	`)
	blocks, err := p.parseAll()
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range blocks {
		t.Log(b.Keys)
		t.Log(b.Tokens)
	}
	if len(blocks) != 1 {
		t.Fatalf("Expect exactly one server block. Got %d.", len(blocks))
	}
	if actual, expected := blocks[0].Keys[0], "http://example.com"; expected != actual {
		t.Errorf("Expected server name to be '%s' but was '%s'", expected, actual)
	}
	if len(blocks[0].Tokens) != 2 {
		t.Fatalf("Server block should have tokens from import")
	}
	if actual, expected := blocks[0].Tokens["gzip"][0].Text, "gzip"; expected != actual {
		t.Errorf("Expected argument to be '%s' but was '%s'", expected, actual)
	}
	if actual, expected := blocks[0].Tokens["errors"][1].Text, "stderr"; expected != actual {
		t.Errorf("Expected argument to be '%s' but was '%s'", expected, actual)
	}

}

func writeStringToTempFileOrDie(t *testing.T, str string) (pathToFile string) {
	file, err := ioutil.TempFile("", t.Name())
	if err != nil {
		panic(err) // get a stack trace so we know where this was called from.
	}
	if _, err := file.WriteString(str); err != nil {
		panic(err)
	}
	if err := file.Close(); err != nil {
		panic(err)
	}
	return file.Name()
}

func TestImportedFilesIgnoreNonDirectiveImportTokens(t *testing.T) {
	fileName := writeStringToTempFileOrDie(t, `
		http://example.com {
			# This isn't an import directive, it's just an arg with value 'import'
			basicauth / import password
		}
	`)
	// Parse the root file that imports the other one.
	p := testParser(`import ` + fileName)
	blocks, err := p.parseAll()
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range blocks {
		t.Log(b.Keys)
		t.Log(b.Tokens)
	}
	auth := blocks[0].Tokens["basicauth"]
	line := auth[0].Text + " " + auth[1].Text + " " + auth[2].Text + " " + auth[3].Text
	if line != "basicauth / import password" {
		// Previously, it would be changed to:
		//   basicauth / import /path/to/test/dir/password
		// referencing a file that (probably) doesn't exist and changing the
		// password!
		t.Errorf("Expected basicauth tokens to be 'basicauth / import password' but got %#q", line)
	}
}

func TestSnippetAcrossMultipleFiles(t *testing.T) {
	// Make the derived Caddyfile that expects (common) to be defined.
	fileName := writeStringToTempFileOrDie(t, `
		http://example.com {
			import common
		}
	`)

	// Parse the root file that defines (common) and then imports the other one.
	p := testParser(`
		(common) {
			gzip foo
		}
		import ` + fileName + `
	`)

	blocks, err := p.parseAll()
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range blocks {
		t.Log(b.Keys)
		t.Log(b.Tokens)
	}
	if len(blocks) != 1 {
		t.Fatalf("Expect exactly one server block. Got %d.", len(blocks))
	}
	if actual, expected := blocks[0].Keys[0], "http://example.com"; expected != actual {
		t.Errorf("Expected server name to be '%s' but was '%s'", expected, actual)
	}
	if len(blocks[0].Tokens) != 1 {
		t.Fatalf("Server block should have tokens from import")
	}
	if actual, expected := blocks[0].Tokens["gzip"][0].Text, "gzip"; expected != actual {
		t.Errorf("Expected argument to be '%s' but was '%s'", expected, actual)
	}
}
