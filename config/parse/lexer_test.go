package parse

import (
	"strings"
	"testing"
)

type lexerTestCase struct {
	input    string
	expected []token
}

func TestLexer(t *testing.T) {
	testCases := []lexerTestCase{
		{
			input: `host:123`,
			expected: []token{
				{line: 1, text: "host:123"},
			},
		},
		{
			input: `host:123

					directive`,
			expected: []token{
				{line: 1, text: "host:123"},
				{line: 3, text: "directive"},
			},
		},
		{
			input: `host:123 {
						directive
					}`,
			expected: []token{
				{line: 1, text: "host:123"},
				{line: 1, text: "{"},
				{line: 2, text: "directive"},
				{line: 3, text: "}"},
			},
		},
		{
			input: `host:123 { directive }`,
			expected: []token{
				{line: 1, text: "host:123"},
				{line: 1, text: "{"},
				{line: 1, text: "directive"},
				{line: 1, text: "}"},
			},
		},
		{
			input: `host:123 {
						#comment
						directive
						# comment
						foobar # another comment
					}`,
			expected: []token{
				{line: 1, text: "host:123"},
				{line: 1, text: "{"},
				{line: 3, text: "directive"},
				{line: 5, text: "foobar"},
				{line: 6, text: "}"},
			},
		},
		{
			input: `a "quoted value" b
					foobar`,
			expected: []token{
				{line: 1, text: "a"},
				{line: 1, text: "quoted value"},
				{line: 1, text: "b"},
				{line: 2, text: "foobar"},
			},
		},
		{
			input: `A "quoted \"value\" inside" B`,
			expected: []token{
				{line: 1, text: "A"},
				{line: 1, text: `quoted "value" inside`},
				{line: 1, text: "B"},
			},
		},
		{
			input: `"don't\escape"`,
			expected: []token{
				{line: 1, text: `don't\escape`},
			},
		},
		{
			input: `"don't\\escape"`,
			expected: []token{
				{line: 1, text: `don't\\escape`},
			},
		},
		{
			input: `A "quoted value with line
					break inside" {
						foobar
					}`,
			expected: []token{
				{line: 1, text: "A"},
				{line: 1, text: "quoted value with line\n\t\t\t\t\tbreak inside"},
				{line: 2, text: "{"},
				{line: 3, text: "foobar"},
				{line: 4, text: "}"},
			},
		},
		{
			input: `"C:\php\php-cgi.exe"`,
			expected: []token{
				{line: 1, text: `C:\php\php-cgi.exe`},
			},
		},
		{
			input: `empty "" string`,
			expected: []token{
				{line: 1, text: `empty`},
				{line: 1, text: ``},
				{line: 1, text: `string`},
			},
		},
		{
			input: "skip those\r\nCR characters",
			expected: []token{
				{line: 1, text: "skip"},
				{line: 1, text: "those"},
				{line: 2, text: "CR"},
				{line: 2, text: "characters"},
			},
		},
	}

	for i, testCase := range testCases {
		actual := tokenize(testCase.input)
		lexerCompare(t, i, testCase.expected, actual)
	}
}

func tokenize(input string) (tokens []token) {
	l := lexer{}
	l.load(strings.NewReader(input))
	for l.next() {
		tokens = append(tokens, l.token)
	}
	return
}

func lexerCompare(t *testing.T, n int, expected, actual []token) {
	if len(expected) != len(actual) {
		t.Errorf("Test case %d: expected %d token(s) but got %d", n, len(expected), len(actual))
	}

	for i := 0; i < len(actual) && i < len(expected); i++ {
		if actual[i].line != expected[i].line {
			t.Errorf("Test case %d token %d ('%s'): expected line %d but was line %d",
				n, i, expected[i].text, expected[i].line, actual[i].line)
			break
		}
		if actual[i].text != expected[i].text {
			t.Errorf("Test case %d token %d: expected text '%s' but was '%s'",
				n, i, expected[i].text, actual[i].text)
			break
		}
	}
}
