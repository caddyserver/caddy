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
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"
	"unicode"
)

type (
	// lexer is a utility which can get values, token by
	// token, from a Reader. A token is a word, and tokens
	// are separated by whitespace. A word can be enclosed
	// in quotes if it contains whitespace.
	lexer struct {
		reader       *bufio.Reader
		token        Token
		line         int
		skippedLines int
	}

	// Token represents a single parsable unit.
	Token struct {
		File    string
		Line    int
		Text    string
		Heredoc int
	}
)

// load prepares the lexer to scan an input for tokens.
// It discards any leading byte order mark.
func (l *lexer) load(input io.Reader) error {
	l.reader = bufio.NewReader(input)
	l.line = 1

	// discard byte order mark, if present
	firstCh, _, err := l.reader.ReadRune()
	if err != nil {
		return err
	}
	if firstCh != 0xFEFF {
		err := l.reader.UnreadRune()
		if err != nil {
			return err
		}
	}

	return nil
}

// next loads the next token into the lexer.
// A token is delimited by whitespace, unless
// the token starts with a quotes character (")
// in which case the token goes until the closing
// quotes (the enclosing quotes are not included).
// Inside quoted strings, quotes may be escaped
// with a preceding \ character. No other chars
// may be escaped. The rest of the line is skipped
// if a "#" character is read in. Returns true if
// a token was loaded; false otherwise.
func (l *lexer) next() bool {
	var val []rune
	var comment, quoted, btQuoted, inHeredoc, escaped bool
	var heredocMarker string
	var heredocEscaped bool

	makeToken := func() bool {
		l.token.Text = string(val)
		return true
	}

	for {
		// Read a character in; if err then if we had
		// read some characters, make a token. If we
		// reached EOF, then no more tokens to read.
		// If no EOF, then we had a problem.
		ch, _, err := l.reader.ReadRune()
		if err != nil {
			if len(val) > 0 {
				return makeToken()
			}
			if err == io.EOF {
				return false
			}
			panic(err)
		}

		// detect whether we have the start of a heredoc
		if !inHeredoc && !heredocEscaped && len(val) > 1 && string(val[:2]) == "<<" {
			if ch == '<' {
				panic(fmt.Errorf("too many '<' for heredoc"))
			}
			if ch == '\r' {
				continue
			}
			// after hitting a newline, we know that the heredoc marker
			// is the characters after the two << and the newline.
			// we reset the val because the heredoc is syntax we don't
			// want to keep.
			if ch == '\n' {
				inHeredoc = true
				heredocMarker = string(val[2:])
				l.skippedLines++
				val = nil
				continue
			}
			val = append(val, ch)
			continue
		}

		// if we're in a heredoc, all characters are read as-is
		if inHeredoc {
			val = append(val, ch)

			if ch == '\n' {
				l.skippedLines++
			}

			// check if we're done, i.e. that the last few characters are the marker
			if len(val) > len(heredocMarker) && string(val[len(val)-len(heredocMarker):]) == heredocMarker {
				// find the last newline of the heredoc, which is where the contents end
				lastNewline := strings.LastIndex(string(val), "\n")

				// figure out how much whitespace we need to strip from the front of every line
				paddingToStrip := string(val[lastNewline+1 : len(val)-len(heredocMarker)])

				// collapse the content, then split into separate lines
				lines := strings.Split(string(val[:lastNewline+1]), "\n")

				// iterate over each line and strip the whitespace from the front
				var out string
				for i, line := range lines[:len(lines)-1] {
					// find an exact match for the padding
					index := strings.Index(line, paddingToStrip)

					// if the padding doesn't match exactly at the start then we can't safely strip
					if index != 0 {
						panic(fmt.Errorf("mismatched whitespace in heredoc on line #%d [%s], expected whitespace [%s]", i, line, paddingToStrip))
					}

					// strip, then append the line, with the newline, to the output.
					// also removes all "\r" because Windows.
					out += strings.ReplaceAll(line[len(paddingToStrip):]+"\n", "\r", "")
				}

				// set the final value
				val = []rune(out)

				// set the line counter
				l.line += l.skippedLines
				l.skippedLines = 0

				// adds +1 to the count of newlines in the token text
				// for the parser to track whether we're still on
				// the same directive; this is a hack, because we
				// consume the first newline in the heredoc, so
				// it throws off the line count.
				l.token.Heredoc = 1

				return makeToken()
			}

			// stay in the heredoc until we find the ending marker
			continue
		}

		// track whether we found an escape '\' for the next
		// iteration to be contextually aware
		if !escaped && !btQuoted && ch == '\\' {
			escaped = true
			continue
		}

		if quoted || btQuoted {
			if quoted && escaped {
				// all is literal in quoted area,
				// so only escape quotes
				if ch != '"' {
					val = append(val, '\\')
				}
				escaped = false
			} else {
				// check if we reached the end of the quoted token
				if (quoted && ch == '"') || (btQuoted && ch == '`') {
					return makeToken()
				}
			}
			// allow quoted text to wrap continue on multiple lines
			if ch == '\n' {
				l.line += 1 + l.skippedLines
				l.skippedLines = 0
			}
			// collect this character as part of the quoted token
			val = append(val, ch)
			continue
		}

		if unicode.IsSpace(ch) {
			// ignore CR altogether, we only actually care about LF (\n)
			if ch == '\r' {
				continue
			}
			// end of the line
			if ch == '\n' {
				// newlines can be escaped to chain arguments
				// onto multiple lines; else, increment the line count
				if escaped {
					l.skippedLines++
					escaped = false
				} else {
					l.line += 1 + l.skippedLines
					l.skippedLines = 0
				}
				// comments (#) are single-line only
				comment = false
			}
			// any kind of space means we're at the end of this token
			if len(val) > 0 {
				return makeToken()
			}
			continue
		}

		// comments must be at the start of a token,
		// in other words, preceded by space or newline
		if ch == '#' && len(val) == 0 {
			comment = true
		}
		if comment {
			continue
		}

		if len(val) == 0 {
			l.token = Token{Line: l.line}
			if ch == '"' {
				quoted = true
				continue
			}
			if ch == '`' {
				btQuoted = true
				continue
			}
		}

		if escaped {
			// allow escaping the first < to skip the heredoc syntax
			if ch == '<' {
				heredocEscaped = true
			} else {
				val = append(val, '\\')
			}
			escaped = false
		}

		val = append(val, ch)
	}
}

// Tokenize takes bytes as input and lexes it into
// a list of tokens that can be parsed as a Caddyfile.
// Also takes a filename to fill the token's File as
// the source of the tokens, which is important to
// determine relative paths for `import` directives.
func Tokenize(input []byte, filename string) ([]Token, error) {
	l := lexer{}
	if err := l.load(bytes.NewReader(input)); err != nil {
		return nil, err
	}
	var tokens []Token
	for l.next() {
		l.token.File = filename
		tokens = append(tokens, l.token)
	}
	return tokens, nil
}
