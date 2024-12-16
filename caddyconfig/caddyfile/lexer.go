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
	"bufio"
	"bytes"
	"fmt"
	"io"
	"regexp"
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
		File          string
		imports       []string
		Line          int
		Text          string
		wasQuoted     rune // enclosing quote character, if any
		heredocMarker string
		snippetName   string
	}
)

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
	for {
		found, err := l.next()
		if err != nil {
			return nil, err
		}
		if !found {
			break
		}
		l.token.File = filename
		tokens = append(tokens, l.token)
	}
	return tokens, nil
}

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
func (l *lexer) next() (bool, error) {
	var val []rune
	var comment, quoted, btQuoted, inHeredoc, heredocEscaped, escaped bool
	var heredocMarker string

	makeToken := func(quoted rune) bool {
		l.token.Text = string(val)
		l.token.wasQuoted = quoted
		l.token.heredocMarker = heredocMarker
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
				if inHeredoc {
					return false, fmt.Errorf("incomplete heredoc <<%s on line #%d, expected ending marker %s", heredocMarker, l.line+l.skippedLines, heredocMarker)
				}

				return makeToken(0), nil
			}
			if err == io.EOF {
				return false, nil
			}
			return false, err
		}

		// detect whether we have the start of a heredoc
		if !(quoted || btQuoted) && !(inHeredoc || heredocEscaped) &&
			len(val) > 1 && string(val[:2]) == "<<" {
			// a space means it's just a regular token and not a heredoc
			if ch == ' ' {
				return makeToken(0), nil
			}

			// skip CR, we only care about LF
			if ch == '\r' {
				continue
			}

			// after hitting a newline, we know that the heredoc marker
			// is the characters after the two << and the newline.
			// we reset the val because the heredoc is syntax we don't
			// want to keep.
			if ch == '\n' {
				if len(val) == 2 {
					return false, fmt.Errorf("missing opening heredoc marker on line #%d; must contain only alpha-numeric characters, dashes and underscores; got empty string", l.line)
				}

				// check if there's too many <
				if string(val[:3]) == "<<<" {
					return false, fmt.Errorf("too many '<' for heredoc on line #%d; only use two, for example <<END", l.line)
				}

				heredocMarker = string(val[2:])
				if !heredocMarkerRegexp.Match([]byte(heredocMarker)) {
					return false, fmt.Errorf("heredoc marker on line #%d must contain only alpha-numeric characters, dashes and underscores; got '%s'", l.line, heredocMarker)
				}

				inHeredoc = true
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
			if len(val) >= len(heredocMarker) && heredocMarker == string(val[len(val)-len(heredocMarker):]) {
				// set the final value
				val, err = l.finalizeHeredoc(val, heredocMarker)
				if err != nil {
					return false, err
				}

				// set the line counter, and make the token
				l.line += l.skippedLines
				l.skippedLines = 0
				return makeToken('<'), nil
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
				if (quoted && ch == '"') || (btQuoted && ch == '`') {
					return makeToken(ch), nil
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
				return makeToken(0), nil
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

// finalizeHeredoc takes the runes read as the heredoc text and the marker,
// and processes the text to strip leading whitespace, returning the final
// value without the leading whitespace.
func (l *lexer) finalizeHeredoc(val []rune, marker string) ([]rune, error) {
	stringVal := string(val)

	// find the last newline of the heredoc, which is where the contents end
	lastNewline := strings.LastIndex(stringVal, "\n")

	// collapse the content, then split into separate lines
	lines := strings.Split(stringVal[:lastNewline+1], "\n")

	// figure out how much whitespace we need to strip from the front of every line
	// by getting the string that precedes the marker, on the last line
	paddingToStrip := stringVal[lastNewline+1 : len(stringVal)-len(marker)]

	// iterate over each line and strip the whitespace from the front
	var out string
	for lineNum, lineText := range lines[:len(lines)-1] {
		if lineText == "" || lineText == "\r" {
			out += "\n"
			continue
		}

		// find an exact match for the padding
		index := strings.Index(lineText, paddingToStrip)

		// if the padding doesn't match exactly at the start then we can't safely strip
		if index != 0 {
			return nil, fmt.Errorf("mismatched leading whitespace in heredoc <<%s on line #%d [%s], expected whitespace [%s] to match the closing marker", marker, l.line+lineNum+1, lineText, paddingToStrip)
		}

		// strip, then append the line, with the newline, to the output.
		// also removes all "\r" because Windows.
		out += strings.ReplaceAll(lineText[len(paddingToStrip):]+"\n", "\r", "")
	}

	// Remove the trailing newline from the loop
	if len(out) > 0 && out[len(out)-1] == '\n' {
		out = out[:len(out)-1]
	}

	// return the final value
	return []rune(out), nil
}

// Quoted returns true if the token was enclosed in quotes
// (i.e. double quotes, backticks, or heredoc).
func (t Token) Quoted() bool {
	return t.wasQuoted > 0
}

// NumLineBreaks counts how many line breaks are in the token text.
func (t Token) NumLineBreaks() int {
	lineBreaks := strings.Count(t.Text, "\n")
	if t.wasQuoted == '<' {
		// heredocs have an extra linebreak because the opening
		// delimiter is on its own line and is not included in the
		// token Text itself, and the trailing newline is removed.
		lineBreaks += 2
	}
	return lineBreaks
}

// Clone returns a deep copy of the token.
func (t Token) Clone() Token {
	return Token{
		File:          t.File,
		imports:       append([]string{}, t.imports...),
		Line:          t.Line,
		Text:          t.Text,
		wasQuoted:     t.wasQuoted,
		heredocMarker: t.heredocMarker,
		snippetName:   t.snippetName,
	}
}

var heredocMarkerRegexp = regexp.MustCompile("^[A-Za-z0-9_-]+$")

// isNextOnNewLine tests whether t2 is on a different line from t1
func isNextOnNewLine(t1, t2 Token) bool {
	// If the second token is from a different file,
	// we can assume it's from a different line
	if t1.File != t2.File {
		return true
	}

	// If the second token is from a different import chain,
	// we can assume it's from a different line
	if len(t1.imports) != len(t2.imports) {
		return true
	}
	for i, im := range t1.imports {
		if im != t2.imports[i] {
			return true
		}
	}

	// If the first token (incl line breaks) ends
	// on a line earlier than the next token,
	// then the second token is on a new line
	return t1.Line+t1.NumLineBreaks() < t2.Line
}
