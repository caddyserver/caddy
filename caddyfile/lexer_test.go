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
	"strings"
	"testing"
)

type lexerTestCase struct {
	input    string
	expected []Token
}

func TestLexer(t *testing.T) {
	testCases := []lexerTestCase{
		{
			input: `host:123`,
			expected: []Token{
				{Line: 1, Quoted: false, Text: "host:123"},
			},
		},
		{
			input: `host:123

					directive`,
			expected: []Token{
				{Line: 1, Quoted: false, Text: "host:123"},
				{Line: 3, Quoted: false, Text: "directive"},
			},
		},
		{
			input: `host:123 {
						directive
					}`,
			expected: []Token{
				{Line: 1, Quoted: false, Text: "host:123"},
				{Line: 1, Quoted: false, Text: "{"},
				{Line: 2, Quoted: false, Text: "directive"},
				{Line: 3, Quoted: false, Text: "}"},
			},
		},
		{
			input: `host:123 { directive }`,
			expected: []Token{
				{Line: 1, Quoted: false, Text: "host:123"},
				{Line: 1, Quoted: false, Text: "{"},
				{Line: 1, Quoted: false, Text: "directive"},
				{Line: 1, Quoted: false, Text: "}"},
			},
		},
		{
			input: `host:123 {
						#comment
						directive
						# comment
						foobar # another comment
					}`,
			expected: []Token{
				{Line: 1, Quoted: false, Text: "host:123"},
				{Line: 1, Quoted: false, Text: "{"},
				{Line: 3, Quoted: false, Text: "directive"},
				{Line: 5, Quoted: false, Text: "foobar"},
				{Line: 6, Quoted: false, Text: "}"},
			},
		},
		{
			input: `a "quoted value" b
					foobar`,
			expected: []Token{
				{Line: 1, Quoted: false, Text: "a"},
				{Line: 1, Quoted: true, Text: "quoted value"},
				{Line: 1, Quoted: false, Text: "b"},
				{Line: 2, Quoted: false, Text: "foobar"},
			},
		},
		{
			input: `A "quoted \"value\" inside" B`,
			expected: []Token{
				{Line: 1, Quoted: false, Text: "A"},
				{Line: 1, Quoted: true, Text: `quoted "value" inside`},
				{Line: 1, Quoted: false, Text: "B"},
			},
		},
		{
			input: `"don't\escape"`,
			expected: []Token{
				{Line: 1, Quoted: true, Text: `don't\escape`},
			},
		},
		{
			input: `"don't\\escape"`,
			expected: []Token{
				{Line: 1, Quoted: true, Text: `don't\\escape`},
			},
		},
		{
			input: `A "quoted value with line
					break inside" {
						foobar
					}`,
			expected: []Token{
				{Line: 1, Quoted: false, Text: "A"},
				{Line: 1, Quoted: true, Text: "quoted value with line\n\t\t\t\t\tbreak inside"},
				{Line: 2, Quoted: false, Text: "{"},
				{Line: 3, Quoted: false, Text: "foobar"},
				{Line: 4, Quoted: false, Text: "}"},
			},
		},
		{
			input: `"C:\php\php-cgi.exe"`,
			expected: []Token{
				{Line: 1, Quoted: true, Text: `C:\php\php-cgi.exe`},
			},
		},
		{
			input: `empty "" string`,
			expected: []Token{
				{Line: 1, Quoted: false, Text: `empty`},
				{Line: 1, Quoted: true, Text: ``},
				{Line: 1, Quoted: false, Text: `string`},
			},
		},
		{
			input: "skip those\r\nCR characters",
			expected: []Token{
				{Line: 1, Quoted: false, Text: "skip"},
				{Line: 1, Quoted: false, Text: "those"},
				{Line: 2, Quoted: false, Text: "CR"},
				{Line: 2, Quoted: false, Text: "characters"},
			},
		},
		{
			input: "\xEF\xBB\xBF:8080", // test with leading byte order mark
			expected: []Token{
				{Line: 1, Quoted: false, Text: ":8080"},
			},
		},
	}

	for i, testCase := range testCases {
		actual := tokenize(testCase.input)
		lexerCompare(t, i, testCase.expected, actual)
	}
}

func tokenize(input string) (tokens []Token) {
	l := lexer{}
	l.load(strings.NewReader(input))
	for l.next() {
		tokens = append(tokens, l.token)
	}
	return
}

func lexerCompare(t *testing.T, n int, expected, actual []Token) {
	if len(expected) != len(actual) {
		t.Errorf("Test case %d: expected %d token(s) but got %d", n, len(expected), len(actual))
	}

	for i := 0; i < len(actual) && i < len(expected); i++ {
		if actual[i].Line != expected[i].Line {
			t.Errorf("Test case %d token %d ('%s'): expected line %d but was line %d",
				n, i, expected[i].Text, expected[i].Line, actual[i].Line)
			break
		}
		if actual[i].Quoted != expected[i].Quoted {
			t.Errorf("Test case %d token %d ('%s'): expected quoted %t but was quoted %t",
				n, i, expected[i].Text, expected[i].Quoted, actual[i].Quoted)
			break
		}
		if actual[i].Text != expected[i].Text {
			t.Errorf("Test case %d token %d: expected text '%s' but was '%s'",
				n, i, expected[i].Text, actual[i].Text)
			break
		}
	}
}
