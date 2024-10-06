// Copyright 2015 Matthew Holt and The Caddy Authors
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
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestParseVariadic(t *testing.T) {
	args := make([]string, 10)
	for i, tc := range []struct {
		input  string
		result bool
	}{
		{
			input:  "",
			result: false,
		},
		{
			input:  "{args[1",
			result: false,
		},
		{
			input:  "1]}",
			result: false,
		},
		{
			input:  "{args[:]}aaaaa",
			result: false,
		},
		{
			input:  "aaaaa{args[:]}",
			result: false,
		},
		{
			input:  "{args.}",
			result: false,
		},
		{
			input:  "{args.1}",
			result: false,
		},
		{
			input:  "{args[]}",
			result: false,
		},
		{
			input:  "{args[:]}",
			result: true,
		},
		{
			input:  "{args[:]}",
			result: true,
		},
		{
			input:  "{args[0:]}",
			result: true,
		},
		{
			input:  "{args[:0]}",
			result: true,
		},
		{
			input:  "{args[-1:]}",
			result: false,
		},
		{
			input:  "{args[:11]}",
			result: false,
		},
		{
			input:  "{args[10:0]}",
			result: false,
		},
		{
			input:  "{args[0:10]}",
			result: true,
		},
		{
			input:  "{args[0]}:{args[1]}:{args[2]}",
			result: false,
		},
	} {
		token := Token{
			File: "test",
			Line: 1,
			Text: tc.input,
		}
		if v, _, _ := parseVariadic(token, len(args)); v != tc.result {
			t.Errorf("Test %d error expectation failed Expected: %t, got %t", i, tc.result, v)
		}
	}
}

func TestAllTokens(t *testing.T) {
	input := []byte("a b c\nd e")
	expected := []string{"a", "b", "c", "d", "e"}
	tokens, err := allTokens("TestAllTokens", input)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(tokens) != len(expected) {
		t.Fatalf("Expected %d tokens, got %d", len(expected), len(tokens))
	}

	for i, val := range expected {
		if tokens[i].Text != val {
			t.Errorf("Token %d should be '%s' but was '%s'", i, val, tokens[i].Text)
		}
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
		numTokens []int // number of tokens to expect in each segment
	}{
		{`localhost`, false, []string{
			"localhost",
		}, []int{}},

		{`localhost
		  dir1`, false, []string{
			"localhost",
		}, []int{1}},

		{
			`localhost:1234
		  dir1 foo bar`, false, []string{
				"localhost:1234",
			}, []int{3},
		},

		{`localhost {
		    dir1
		  }`, false, []string{
			"localhost",
		}, []int{1}},

		{`localhost:1234 {
		    dir1 foo bar
		    dir2
		  }`, false, []string{
			"localhost:1234",
		}, []int{3, 1}},

		{`http://localhost https://localhost
		  dir1 foo bar`, false, []string{
			"http://localhost",
			"https://localhost",
		}, []int{3}},

		{`http://localhost https://localhost {
		    dir1 foo bar
		  }`, false, []string{
			"http://localhost",
			"https://localhost",
		}, []int{3}},

		{`http://localhost, https://localhost {
		    dir1 foo bar
		  }`, false, []string{
			"http://localhost",
			"https://localhost",
		}, []int{3}},

		{`http://localhost, {
		  }`, true, []string{
			"http://localhost",
		}, []int{}},

		{`host1:80, http://host2.com
		  dir1 foo bar
		  dir2 baz`, false, []string{
			"host1:80",
			"http://host2.com",
		}, []int{3, 2}},

		{`http://host1.com,
		  http://host2.com,
		  https://host3.com`, false, []string{
			"http://host1.com",
			"http://host2.com",
			"https://host3.com",
		}, []int{}},

		{`http://host1.com:1234, https://host2.com
		  dir1 foo {
		    bar baz
		  }
		  dir2`, false, []string{
			"http://host1.com:1234",
			"https://host2.com",
		}, []int{6, 1}},

		{`127.0.0.1
		  dir1 {
		    bar baz
		  }
		  dir2 {
		    foo bar
		  }`, false, []string{
			"127.0.0.1",
		}, []int{5, 5}},

		{`localhost
		  dir1 {
		    foo`, true, []string{
			"localhost",
		}, []int{3}},

		{`localhost
		  dir1 {
		  }`, false, []string{
			"localhost",
		}, []int{3}},

		{`localhost
		  dir1 {
		  } }`, true, []string{
			"localhost",
		}, []int{}},

		{`localhost{
		    dir1
		  }`, true, []string{}, []int{}},

		{`localhost
		  dir1 {
		    nested {
		      foo
		    }
		  }
		  dir2 foo bar`, false, []string{
			"localhost",
		}, []int{7, 3}},

		{``, false, []string{}, []int{}},

		{`localhost
		  dir1 arg1
		  import testdata/import_test1.txt`, false, []string{
			"localhost",
		}, []int{2, 3, 1}},

		{`import testdata/import_test2.txt`, false, []string{
			"host1",
		}, []int{1, 2}},

		{`import testdata/not_found.txt`, true, []string{}, []int{}},

		// empty file should just log a warning, and result in no tokens
		{`import testdata/empty.txt`, false, []string{}, []int{}},

		{`import testdata/only_white_space.txt`, false, []string{}, []int{}},

		// import path/to/dir/* should skip any files that start with a . when iterating over them.
		{`localhost
		  dir1 arg1
		  import testdata/glob/*`, false, []string{
			"localhost",
		}, []int{2, 3, 1}},

		// import path/to/dir/.* should continue to read all dotfiles in a dir.
		{`import testdata/glob/.*`, false, []string{
			"host1",
		}, []int{1, 2}},

		{`""`, false, []string{}, []int{}},

		{``, false, []string{}, []int{}},

		// Unexpected next token after '{' on same line
		{`localhost
		  dir1 { a b }`, true, []string{"localhost"}, []int{}},

		// Unexpected '{' on a new line
		{`localhost
		dir1
		{
			a b
		}`, true, []string{"localhost"}, []int{}},

		// Workaround with quotes
		{`localhost
		  dir1 "{" a b "}"`, false, []string{"localhost"}, []int{5}},

		// Unexpected '{}' at end of line
		{`localhost
		  dir1 {}`, true, []string{"localhost"}, []int{}},
		// Workaround with quotes
		{`localhost
		  dir1 "{}"`, false, []string{"localhost"}, []int{2}},

		// import with args
		{`import testdata/import_args0.txt a`, false, []string{"a"}, []int{}},
		{`import testdata/import_args1.txt a b`, false, []string{"a", "b"}, []int{}},
		{`import testdata/import_args*.txt a b`, false, []string{"a"}, []int{2}},

		// test cases found by fuzzing!
		{`import }{$"`, true, []string{}, []int{}},
		{`import /*/*.txt`, true, []string{}, []int{}},
		{`import /???/?*?o`, true, []string{}, []int{}},
		{`import /??`, true, []string{}, []int{}},
		{`import /[a-z]`, true, []string{}, []int{}},
		{`import {$}`, true, []string{}, []int{}},
		{`import {%}`, true, []string{}, []int{}},
		{`import {$$}`, true, []string{}, []int{}},
		{`import {%%}`, true, []string{}, []int{}},
	} {
		result, err := testParseOne(test.input)

		if test.shouldErr && err == nil {
			t.Errorf("Test %d: Expected an error, but didn't get one", i)
		}
		if !test.shouldErr && err != nil {
			t.Errorf("Test %d: Expected no error, but got: %v", i, err)
		}

		// t.Logf("%+v\n", result)
		if len(result.Keys) != len(test.keys) {
			t.Errorf("Test %d: Expected %d keys, got %d",
				i, len(test.keys), len(result.Keys))
			continue
		}
		for j, addr := range result.GetKeysText() {
			if addr != test.keys[j] {
				t.Errorf("Test %d, key %d: Expected '%s', but was '%s'",
					i, j, test.keys[j], addr)
			}
		}

		if len(result.Segments) != len(test.numTokens) {
			t.Errorf("Test %d: Expected %d segments, had %d",
				i, len(test.numTokens), len(result.Segments))
			continue
		}

		for j, seg := range result.Segments {
			if len(seg) != test.numTokens[j] {
				t.Errorf("Test %d, segment %d: Expected %d tokens, counted %d",
					i, j, test.numTokens[j], len(seg))
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
		textKeys := got.GetKeysText()
		if len(textKeys) != 1 || textKeys[0] != "localhost" {
			t.Errorf("got keys unexpected: expect localhost, got %v", textKeys)
			return false
		}
		if len(got.Segments) != 2 {
			t.Errorf("got wrong number of segments: expect 2, got %d", len(got.Segments))
			return false
		}
		if len(got.Segments[0]) != 1 || len(got.Segments[1]) != 2 {
			t.Errorf("got unexpected tokens: %v", got.Segments)
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
	err = os.WriteFile(recursiveFile1, []byte(
		`localhost
		dir1
		import recursive_import_test2`), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(recursiveFile1)

	err = os.WriteFile(recursiveFile2, []byte("dir2 1"), 0o644)
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
	err = os.WriteFile(recursiveFile1, []byte(
		`localhost
		dir1
		import `+recursiveFile2), 0o644)
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
		textKeys := got.GetKeysText()
		if len(textKeys) != 1 || textKeys[0] != "localhost" {
			t.Errorf("got keys unexpected: expect localhost, got %v", textKeys)
			return false
		}
		if len(got.Segments) != 2 {
			t.Errorf("got wrong number of segments: expect 2, got %d", len(got.Segments))
			return false
		}
		if len(got.Segments[0]) != 1 || len(got.Segments[1]) != 8 {
			t.Errorf("got unexpected tokens: %v", got.Segments)
			return false
		}
		return true
	}

	directiveFile, err := filepath.Abs("testdata/directive_import_test")
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(directiveFile, []byte(`prop1 1
	prop2 2`), 0o644)
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

		{`foo.example.com   ,   example.com`, false, [][]string{
			{"foo.example.com", "example.com"},
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

		// recursive self-import
		{`import testdata/import_recursive0.txt`, true, [][]string{}},
		{`import testdata/import_recursive3.txt
		import testdata/import_recursive1.txt`, true, [][]string{}},

		// cyclic imports
		{`(A) {
			import A
		}
		:80
		import A
		`, true, [][]string{}},
		{`(A) {
			import B
		}
		(B) {
			import A
		}
		:80
		import A
		`, true, [][]string{}},
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
				t.Errorf("Test %d: Expected %d keys in block %d, got %d: %v",
					i, len(test.keys[j]), j, len(block.Keys), block.Keys)
				continue
			}
			for k, addr := range block.GetKeysText() {
				if addr != test.keys[j][k] {
					t.Errorf("Test %d, block %d, key %d: Expected '%s', but got '%s'",
						i, j, k, test.keys[j][k], addr)
				}
			}
		}
	}
}

func TestEnvironmentReplacement(t *testing.T) {
	os.Setenv("FOOBAR", "foobar")
	os.Setenv("CHAINED", "$FOOBAR")

	for i, test := range []struct {
		input  string
		expect string
	}{
		{
			input:  "",
			expect: "",
		},
		{
			input:  "foo",
			expect: "foo",
		},
		{
			input:  "{$NOT_SET}",
			expect: "",
		},
		{
			input:  "foo{$NOT_SET}bar",
			expect: "foobar",
		},
		{
			input:  "{$FOOBAR}",
			expect: "foobar",
		},
		{
			input:  "foo {$FOOBAR} bar",
			expect: "foo foobar bar",
		},
		{
			input:  "foo{$FOOBAR}bar",
			expect: "foofoobarbar",
		},
		{
			input:  "foo\n{$FOOBAR}\nbar",
			expect: "foo\nfoobar\nbar",
		},
		{
			input:  "{$FOOBAR} {$FOOBAR}",
			expect: "foobar foobar",
		},
		{
			input:  "{$FOOBAR}{$FOOBAR}",
			expect: "foobarfoobar",
		},
		{
			input:  "{$CHAINED}",
			expect: "$FOOBAR", // should not chain env expands
		},
		{
			input:  "{$FOO:default}",
			expect: "default",
		},
		{
			input:  "foo{$BAR:bar}baz",
			expect: "foobarbaz",
		},
		{
			input:  "foo{$BAR:$FOOBAR}baz",
			expect: "foo$FOOBARbaz", // should not chain env expands
		},
		{
			input:  "{$FOOBAR",
			expect: "{$FOOBAR",
		},
		{
			input:  "{$LONGER_NAME $FOOBAR}",
			expect: "",
		},
		{
			input:  "{$}",
			expect: "{$}",
		},
		{
			input:  "{$$}",
			expect: "",
		},
		{
			input:  "{$",
			expect: "{$",
		},
		{
			input:  "}{$",
			expect: "}{$",
		},
	} {
		actual := replaceEnvVars([]byte(test.input))
		if !bytes.Equal(actual, []byte(test.expect)) {
			t.Errorf("Test %d: Expected: '%s' but got '%s'", i, test.expect, actual)
		}
	}
}

func TestImportReplacementInJSONWithBrace(t *testing.T) {
	for i, test := range []struct {
		args   []string
		input  string
		expect string
	}{
		{
			args:   []string{"123"},
			input:  "{args[0]}",
			expect: "123",
		},
		{
			args:   []string{"123"},
			input:  `{"key":"{args[0]}"}`,
			expect: `{"key":"123"}`,
		},
		{
			args:   []string{"123", "123"},
			input:  `{"key":[{args[0]},{args[1]}]}`,
			expect: `{"key":[123,123]}`,
		},
	} {
		repl := makeArgsReplacer(test.args)
		actual := repl.ReplaceKnown(test.input, "")
		if actual != test.expect {
			t.Errorf("Test %d: Expected: '%s' but got '%s'", i, test.expect, actual)
		}
	}
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
	if len(blocks) != 1 {
		t.Fatalf("Expect exactly one server block. Got %d.", len(blocks))
	}
	if actual, expected := blocks[0].GetKeysText()[0], "http://example.com"; expected != actual {
		t.Errorf("Expected server name to be '%s' but was '%s'", expected, actual)
	}
	if len(blocks[0].Segments) != 2 {
		t.Fatalf("Server block should have tokens from import, got: %+v", blocks[0])
	}
	if actual, expected := blocks[0].Segments[0][0].Text, "gzip"; expected != actual {
		t.Errorf("Expected argument to be '%s' but was '%s'", expected, actual)
	}
	if actual, expected := blocks[0].Segments[1][1].Text, "stderr"; expected != actual {
		t.Errorf("Expected argument to be '%s' but was '%s'", expected, actual)
	}
}

func writeStringToTempFileOrDie(t *testing.T, str string) (pathToFile string) {
	file, err := os.CreateTemp("", t.Name())
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
			basic_auth / import password
		}
	`)
	// Parse the root file that imports the other one.
	p := testParser(`import ` + fileName)
	blocks, err := p.parseAll()
	if err != nil {
		t.Fatal(err)
	}
	auth := blocks[0].Segments[0]
	line := auth[0].Text + " " + auth[1].Text + " " + auth[2].Text + " " + auth[3].Text
	if line != "basic_auth / import password" {
		// Previously, it would be changed to:
		//   basic_auth / import /path/to/test/dir/password
		// referencing a file that (probably) doesn't exist and changing the
		// password!
		t.Errorf("Expected basic_auth tokens to be 'basic_auth / import password' but got %#q", line)
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
	if len(blocks) != 1 {
		t.Fatalf("Expect exactly one server block. Got %d.", len(blocks))
	}
	if actual, expected := blocks[0].GetKeysText()[0], "http://example.com"; expected != actual {
		t.Errorf("Expected server name to be '%s' but was '%s'", expected, actual)
	}
	if len(blocks[0].Segments) != 1 {
		t.Fatalf("Server block should have tokens from import")
	}
	if actual, expected := blocks[0].Segments[0][0].Text, "gzip"; expected != actual {
		t.Errorf("Expected argument to be '%s' but was '%s'", expected, actual)
	}
}

func TestRejectsGlobalMatcher(t *testing.T) {
	p := testParser(`
		@rejected path /foo

		(common) {
			gzip foo
			errors stderr
		}

		http://example.com {
			import common
		}
	`)
	_, err := p.parseAll()
	if err == nil {
		t.Fatal("Expected an error, but got nil")
	}
	expected := "request matchers may not be defined globally, they must be in a site block; found @rejected, at Testfile:2"
	if err.Error() != expected {
		t.Errorf("Expected error to be '%s' but got '%v'", expected, err)
	}
}

func testParser(input string) parser {
	return parser{Dispenser: NewTestDispenser(input)}
}
