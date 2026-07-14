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
	"reflect"
	"testing"
)

func TestLexer(t *testing.T) {
	testCases := []struct {
		input        []byte
		expected     []Token
		expectErr    bool
		errorMessage string
	}{
		{
			input: []byte(`host:123`),
			expected: []Token{
				{Line: 1, Text: "host:123"},
			},
		},
		{
			input: []byte(`host:123

					directive`),
			expected: []Token{
				{Line: 1, Text: "host:123"},
				{Line: 3, Text: "directive"},
			},
		},
		{
			input: []byte(`host:123 {
						directive
					}`),
			expected: []Token{
				{Line: 1, Text: "host:123"},
				{Line: 1, Text: "{"},
				{Line: 2, Text: "directive"},
				{Line: 3, Text: "}"},
			},
		},
		{
			input: []byte(`host:123 { directive }`),
			expected: []Token{
				{Line: 1, Text: "host:123"},
				{Line: 1, Text: "{"},
				{Line: 1, Text: "directive"},
				{Line: 1, Text: "}"},
			},
		},
		{
			input: []byte(`host:123 {
						#comment
						directive
						# comment
						foobar # another comment
					}`),
			expected: []Token{
				{Line: 1, Text: "host:123"},
				{Line: 1, Text: "{"},
				{Line: 3, Text: "directive"},
				{Line: 5, Text: "foobar"},
				{Line: 6, Text: "}"},
			},
		},
		{
			input: []byte(`host:123 {
						# hash inside string is not a comment
						redir / /some/#/path
					}`),
			expected: []Token{
				{Line: 1, Text: "host:123"},
				{Line: 1, Text: "{"},
				{Line: 3, Text: "redir"},
				{Line: 3, Text: "/"},
				{Line: 3, Text: "/some/#/path"},
				{Line: 4, Text: "}"},
			},
		},
		{
			input: []byte("# comment at beginning of file\n# comment at beginning of line\nhost:123"),
			expected: []Token{
				{Line: 3, Text: "host:123"},
			},
		},
		{
			input: []byte(`a "quoted value" b
					foobar`),
			expected: []Token{
				{Line: 1, Text: "a"},
				{Line: 1, Text: "quoted value"},
				{Line: 1, Text: "b"},
				{Line: 2, Text: "foobar"},
			},
		},
		{
			input: []byte(`A "quoted \"value\" inside" B`),
			expected: []Token{
				{Line: 1, Text: "A"},
				{Line: 1, Text: `quoted "value" inside`},
				{Line: 1, Text: "B"},
			},
		},
		{
			input: []byte("An escaped \"newline\\\ninside\" quotes"),
			expected: []Token{
				{Line: 1, Text: "An"},
				{Line: 1, Text: "escaped"},
				{Line: 1, Text: "newline\\\ninside"},
				{Line: 2, Text: "quotes"},
			},
		},
		{
			input: []byte("An escaped newline\\\noutside quotes"),
			expected: []Token{
				{Line: 1, Text: "An"},
				{Line: 1, Text: "escaped"},
				{Line: 1, Text: "newline"},
				{Line: 1, Text: "outside"},
				{Line: 1, Text: "quotes"},
			},
		},
		{
			input: []byte("line1\\\nescaped\nline2\nline3"),
			expected: []Token{
				{Line: 1, Text: "line1"},
				{Line: 1, Text: "escaped"},
				{Line: 3, Text: "line2"},
				{Line: 4, Text: "line3"},
			},
		},
		{
			input: []byte("line1\\\nescaped1\\\nescaped2\nline4\nline5"),
			expected: []Token{
				{Line: 1, Text: "line1"},
				{Line: 1, Text: "escaped1"},
				{Line: 1, Text: "escaped2"},
				{Line: 4, Text: "line4"},
				{Line: 5, Text: "line5"},
			},
		},
		{
			input: []byte(`"unescapable\ in quotes"`),
			expected: []Token{
				{Line: 1, Text: `unescapable\ in quotes`},
			},
		},
		{
			input: []byte(`"don't\escape"`),
			expected: []Token{
				{Line: 1, Text: `don't\escape`},
			},
		},
		{
			input: []byte(`"don't\\escape"`),
			expected: []Token{
				{Line: 1, Text: `don't\\escape`},
			},
		},
		{
			input: []byte(`un\escapable`),
			expected: []Token{
				{Line: 1, Text: `un\escapable`},
			},
		},
		{
			input: []byte(`A "quoted value with line
					break inside" {
						foobar
					}`),
			expected: []Token{
				{Line: 1, Text: "A"},
				{Line: 1, Text: "quoted value with line\n\t\t\t\t\tbreak inside"},
				{Line: 2, Text: "{"},
				{Line: 3, Text: "foobar"},
				{Line: 4, Text: "}"},
			},
		},
		{
			input: []byte(`"C:\php\php-cgi.exe"`),
			expected: []Token{
				{Line: 1, Text: `C:\php\php-cgi.exe`},
			},
		},
		{
			input: []byte(`empty "" string`),
			expected: []Token{
				{Line: 1, Text: `empty`},
				{Line: 1, Text: ``},
				{Line: 1, Text: `string`},
			},
		},
		{
			input: []byte("skip those\r\nCR characters"),
			expected: []Token{
				{Line: 1, Text: "skip"},
				{Line: 1, Text: "those"},
				{Line: 2, Text: "CR"},
				{Line: 2, Text: "characters"},
			},
		},
		{
			input: []byte("\xEF\xBB\xBF:8080"), // test with leading byte order mark
			expected: []Token{
				{Line: 1, Text: ":8080"},
			},
		},
		{
			input: []byte("simple `backtick quoted` string"),
			expected: []Token{
				{Line: 1, Text: `simple`},
				{Line: 1, Text: `backtick quoted`},
				{Line: 1, Text: `string`},
			},
		},
		{
			input: []byte("multiline `backtick\nquoted\n` string"),
			expected: []Token{
				{Line: 1, Text: `multiline`},
				{Line: 1, Text: "backtick\nquoted\n"},
				{Line: 3, Text: `string`},
			},
		},
		{
			input: []byte("nested `\"quotes inside\" backticks` string"),
			expected: []Token{
				{Line: 1, Text: `nested`},
				{Line: 1, Text: `"quotes inside" backticks`},
				{Line: 1, Text: `string`},
			},
		},
		{
			input: []byte("reverse-nested \"`backticks` inside\" quotes"),
			expected: []Token{
				{Line: 1, Text: `reverse-nested`},
				{Line: 1, Text: "`backticks` inside"},
				{Line: 1, Text: `quotes`},
			},
		},
		{
			input: []byte(`heredoc <<EOF
content
EOF same-line-arg
	`),
			expected: []Token{
				{Line: 1, Text: `heredoc`},
				{Line: 1, Text: "content"},
				{Line: 3, Text: `same-line-arg`},
			},
		},
		{
			input: []byte(`heredoc <<VERY-LONG-MARKER
content
VERY-LONG-MARKER same-line-arg
	`),
			expected: []Token{
				{Line: 1, Text: `heredoc`},
				{Line: 1, Text: "content"},
				{Line: 3, Text: `same-line-arg`},
			},
		},
		{
			input: []byte(`heredoc <<EOF
extra-newline

EOF same-line-arg
	`),
			expected: []Token{
				{Line: 1, Text: `heredoc`},
				{Line: 1, Text: "extra-newline\n"},
				{Line: 4, Text: `same-line-arg`},
			},
		},
		{
			input: []byte(`heredoc <<EOF
EOF
	HERE same-line-arg
	`),
			expected: []Token{
				{Line: 1, Text: `heredoc`},
				{Line: 1, Text: ``},
				{Line: 3, Text: `HERE`},
				{Line: 3, Text: `same-line-arg`},
			},
		},
		{
			input: []byte(`heredoc <<EOF
		EOF same-line-arg
	`),
			expected: []Token{
				{Line: 1, Text: `heredoc`},
				{Line: 1, Text: ""},
				{Line: 2, Text: `same-line-arg`},
			},
		},
		{
			input: []byte(`heredoc <<EOF
	content
	EOF same-line-arg
	`),
			expected: []Token{
				{Line: 1, Text: `heredoc`},
				{Line: 1, Text: "content"},
				{Line: 3, Text: `same-line-arg`},
			},
		},
		{
			input: []byte(`prev-line
	heredoc <<EOF
		multi
		line
		content
	EOF same-line-arg
	next-line
	`),
			expected: []Token{
				{Line: 1, Text: `prev-line`},
				{Line: 2, Text: `heredoc`},
				{Line: 2, Text: "\tmulti\n\tline\n\tcontent"},
				{Line: 6, Text: `same-line-arg`},
				{Line: 7, Text: `next-line`},
			},
		},
		{
			input: []byte(`escaped-heredoc \<< >>`),
			expected: []Token{
				{Line: 1, Text: `escaped-heredoc`},
				{Line: 1, Text: `<<`},
				{Line: 1, Text: `>>`},
			},
		},
		{
			input: []byte(`not-a-heredoc <EOF
	content
	`),
			expected: []Token{
				{Line: 1, Text: `not-a-heredoc`},
				{Line: 1, Text: `<EOF`},
				{Line: 2, Text: `content`},
			},
		},
		{
			input: []byte(`not-a-heredoc <<<EOF content`),
			expected: []Token{
				{Line: 1, Text: `not-a-heredoc`},
				{Line: 1, Text: `<<<EOF`},
				{Line: 1, Text: `content`},
			},
		},
		{
			input: []byte(`not-a-heredoc "<<" ">>"`),
			expected: []Token{
				{Line: 1, Text: `not-a-heredoc`},
				{Line: 1, Text: `<<`},
				{Line: 1, Text: `>>`},
			},
		},
		{
			input: []byte(`not-a-heredoc << >>`),
			expected: []Token{
				{Line: 1, Text: `not-a-heredoc`},
				{Line: 1, Text: `<<`},
				{Line: 1, Text: `>>`},
			},
		},
		{
			input: []byte(`not-a-heredoc <<HERE SAME LINE
	content
	HERE same-line-arg
	`),
			expected: []Token{
				{Line: 1, Text: `not-a-heredoc`},
				{Line: 1, Text: `<<HERE`},
				{Line: 1, Text: `SAME`},
				{Line: 1, Text: `LINE`},
				{Line: 2, Text: `content`},
				{Line: 3, Text: `HERE`},
				{Line: 3, Text: `same-line-arg`},
			},
		},
		{
			input: []byte(`heredoc <<s
			�
			s
	`),
			expected: []Token{
				{Line: 1, Text: `heredoc`},
				{Line: 1, Text: "�"},
			},
		},
		{
			input: []byte("\u000Aheredoc \u003C\u003C\u0073\u0073\u000A\u00BF\u0057\u0001\u0000\u00FF\u00FF\u00FF\u00FF\u00FF\u00FF\u00FF\u003D\u001F\u000A\u0073\u0073\u000A\u00BF\u0057\u0001\u0000\u00FF\u00FF\u00FF\u00FF\u00FF\u00FF\u00FF\u003D\u001F\u000A\u00BF\u00BF\u0057\u0001\u0000\u00FF\u00FF\u00FF\u00FF\u00FF\u00FF\u00FF\u003D\u001F"),
			expected: []Token{
				{
					Line: 2,
					Text: "heredoc",
				},
				{
					Line: 2,
					Text: "\u00BF\u0057\u0001\u0000\u00FF\u00FF\u00FF\u00FF\u00FF\u00FF\u00FF\u003D\u001F",
				},
				{
					Line: 5,
					Text: "\u00BF\u0057\u0001\u0000\u00FF\u00FF\u00FF\u00FF\u00FF\u00FF\u00FF\u003D\u001F",
				},
				{
					Line: 6,
					Text: "\u00BF\u00BF\u0057\u0001\u0000\u00FF\u00FF\u00FF\u00FF\u00FF\u00FF\u00FF\u003D\u001F",
				},
			},
		},
		{
			input:        []byte("not-a-heredoc <<\n"),
			expectErr:    true,
			errorMessage: "missing opening heredoc marker on line #1; must contain only alphanumeric characters, dashes and underscores; got empty string",
		},
		{
			input: []byte(`heredoc <<<EOF
	content
	EOF same-line-arg
	`),
			expectErr:    true,
			errorMessage: "too many '<' for heredoc on line #1; only use two, for example <<END",
		},
		{
			input: []byte(`heredoc <<EOF
	content
	`),
			expectErr:    true,
			errorMessage: "incomplete heredoc <<EOF on line #3, expected ending marker EOF",
		},
		{
			input: []byte(`heredoc <<EOF
	content
		EOF
	`),
			expectErr:    true,
			errorMessage: "mismatched leading whitespace in heredoc <<EOF on line #2 [\tcontent], expected whitespace [\t\t] to match the closing marker",
		},
		{
			input: []byte(`heredoc <<EOF
        content
		EOF
	`),
			expectErr:    true,
			errorMessage: "mismatched leading whitespace in heredoc <<EOF on line #2 [        content], expected whitespace [\t\t] to match the closing marker",
		},
		{
			input: []byte(`heredoc <<EOF
The next line is a blank line

The previous line is a blank line
EOF`),
			expected: []Token{
				{Line: 1, Text: "heredoc"},
				{Line: 1, Text: "The next line is a blank line\n\nThe previous line is a blank line"},
			},
		},
		{
			input: []byte(`heredoc <<EOF
	One tab indented heredoc with blank next line

	One tab indented heredoc with blank previous line
	EOF`),
			expected: []Token{
				{Line: 1, Text: "heredoc"},
				{Line: 1, Text: "One tab indented heredoc with blank next line\n\nOne tab indented heredoc with blank previous line"},
			},
		},
		{
			input: []byte(`heredoc <<EOF
The next line is a blank line with one tab
	
The previous line is a blank line with one tab
EOF`),
			expected: []Token{
				{Line: 1, Text: "heredoc"},
				{Line: 1, Text: "The next line is a blank line with one tab\n\t\nThe previous line is a blank line with one tab"},
			},
		},
		{
			input: []byte(`heredoc <<EOF
		The next line is a blank line with one tab less than the correct indentation
	
		The previous line is a blank line with one tab less than the correct indentation
		EOF`),
			expectErr:    true,
			errorMessage: "mismatched leading whitespace in heredoc <<EOF on line #3 [\t], expected whitespace [\t\t] to match the closing marker",
		},
	}

	for i, testCase := range testCases {
		actual, err := Tokenize(testCase.input, "")
		if testCase.expectErr {
			if err == nil {
				t.Fatalf("expected error, got actual: %v", actual)
				continue
			}
			if err.Error() != testCase.errorMessage {
				t.Fatalf("expected error '%v', got: %v", testCase.errorMessage, err)
			}
			continue
		}

		if err != nil {
			t.Fatalf("%v", err)
		}
		lexerCompare(t, i, testCase.expected, actual)
	}
}

func TestTokenFormatModeAccessors(t *testing.T) {
	tok := Token{Text: "hello", raw: `"hello"`, isComment: false}
	if tok.Raw() != `"hello"` {
		t.Errorf("Raw() = %q, want %q", tok.Raw(), `"hello"`)
	}
	// falls back to Text when raw not captured
	if (Token{Text: "hi"}).Raw() != "hi" {
		t.Errorf("Raw() fallback = %q, want %q", (Token{Text: "hi"}).Raw(), "hi")
	}
	c := Token{Text: "# note", raw: "# note", isComment: true}
	if !c.IsComment() {
		t.Error("IsComment() = false, want true")
	}
	// Clone copies the new fields
	clone := c.Clone()
	if clone.raw != c.raw || clone.isComment != c.isComment {
		t.Errorf("Clone did not copy format-mode fields: %+v", clone)
	}
}

func TestLexRawCapture(t *testing.T) {
	cases := []struct {
		in      string
		text    string // processed Text of the single token
		wantRaw string // verbatim source of that token
	}{
		{`hello`, `hello`, `hello`},
		{`"a \"b\" "`, `a "b" `, `"a \"b\" "`},
		{"`raw \"x\"`", `raw "x"`, "`raw \"x\"`"},
		{`\<<NOTHEREDOC`, `<<NOTHEREDOC`, `\<<NOTHEREDOC`},
	}
	for _, c := range cases {
		toks, err := Lex([]byte(c.in), "T", LexOptions{Raw: true})
		if err != nil {
			t.Fatalf("%q: %v", c.in, err)
		}
		if len(toks) != 1 {
			t.Fatalf("%q: got %d tokens, want 1", c.in, len(toks))
		}
		if toks[0].Text != c.text {
			t.Errorf("%q: Text = %q, want %q", c.in, toks[0].Text, c.text)
		}
		if toks[0].Raw() != c.wantRaw {
			t.Errorf("%q: Raw() = %q, want %q", c.in, toks[0].Raw(), c.wantRaw)
		}
	}
}

func TestLexRawCaptureHeredoc(t *testing.T) {
	in := "x <<END\n\thello\n\tEND"
	toks, err := Lex([]byte(in), "T", LexOptions{Raw: true})
	if err != nil {
		t.Fatal(err)
	}
	// token 0 is "x"; token 1 is the heredoc
	if len(toks) != 2 {
		t.Fatalf("got %d tokens, want 2", len(toks))
	}
	// heredoc Text is the de-indented body; Raw is the full framing verbatim.
	if toks[1].Raw() != "<<END\n\thello\n\tEND" {
		t.Errorf("heredoc Raw() = %q, want %q", toks[1].Raw(), "<<END\n\thello\n\tEND")
	}
}

func lexerCompare(t *testing.T, n int, expected, actual []Token) {
	if len(expected) != len(actual) {
		t.Fatalf("Test case %d: expected %d token(s) but got %d", n, len(expected), len(actual))
	}

	for i := 0; i < len(actual) && i < len(expected); i++ {
		if actual[i].Line != expected[i].Line {
			t.Fatalf("Test case %d token %d ('%s'): expected line %d but was line %d",
				n, i, expected[i].Text, expected[i].Line, actual[i].Line)
			break
		}
		if actual[i].Text != expected[i].Text {
			t.Fatalf("Test case %d token %d: expected text '%s' but was '%s'",
				n, i, expected[i].Text, actual[i].Text)
			break
		}
	}
}

func TestLexComments(t *testing.T) {
	toks, err := Lex([]byte("foo # hi there\nbar"), "T", LexOptions{Comments: true, Raw: true})
	if err != nil {
		t.Fatal(err)
	}
	// foo | # hi there | bar
	if len(toks) != 3 {
		t.Fatalf("got %d tokens, want 3: %+v", len(toks), toks)
	}
	if !toks[1].IsComment() || toks[1].Text != "# hi there" {
		t.Errorf("token 1 = %q (comment=%v), want comment %q", toks[1].Text, toks[1].IsComment(), "# hi there")
	}
	if toks[2].Text != "bar" {
		t.Errorf("token 2 = %q, want bar", toks[2].Text)
	}
}

func TestLexHashMidTokenIsLiteral(t *testing.T) {
	toks, err := Lex([]byte("e#f redir /a/#/b"), "T", LexOptions{Comments: true})
	if err != nil {
		t.Fatal(err)
	}
	texts := []string{}
	for _, tk := range toks {
		texts = append(texts, tk.Text)
	}
	want := []string{"e#f", "redir", "/a/#/b"}
	if !reflect.DeepEqual(texts, want) {
		t.Errorf("texts = %v, want %v", texts, want)
	}
	for _, tk := range toks {
		if tk.IsComment() {
			t.Errorf("unexpected comment token %q", tk.Text)
		}
	}
}

func TestLexCommentsDisabledDiscards(t *testing.T) {
	toks, _ := Lex([]byte("foo # hi\nbar"), "T", LexOptions{})
	if len(toks) != 2 {
		t.Fatalf("got %d tokens, want 2 (comment discarded)", len(toks))
	}
}

func TestLexEqualsTokenizeWithZeroOptions(t *testing.T) {
	in := []byte("site {\n\troot * /srv\n\tfile_server\n}\n")
	a, err := Tokenize(in, "Caddyfile")
	if err != nil {
		t.Fatal(err)
	}
	b, err := Lex(in, "Caddyfile", LexOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Errorf("Lex(zero opts) != Tokenize\n a=%+v\n b=%+v", a, b)
	}
}
