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
	"io"
	"slices"
	"unicode"
)

// Format formats the input Caddyfile to a standard, nice-looking
// appearance. It works by reading each rune of the input and taking
// control over all the bracing and whitespace that is written; otherwise,
// words, comments, placeholders, and escaped characters are all treated
// literally and written as they appear in the input.
func Format(input []byte) []byte {
	input = bytes.TrimSpace(input)

	out := new(bytes.Buffer)
	rdr := bytes.NewReader(input)

	type heredocState int

	const (
		heredocClosed  heredocState = 0
		heredocOpening heredocState = 1
		heredocOpened  heredocState = 2
	)

	var (
		last rune // the last character that was written to the result

		space           = true // whether current/previous character was whitespace (beginning of input counts as space)
		beginningOfLine = true // whether we are at beginning of line

		openBrace        bool // whether current word/token is or started with open curly brace
		openBraceWritten bool // if openBrace, whether that brace was written or not
		openBraceSpace   bool // whether there was a non-newline space before open brace

		newLines int // count of newlines consumed

		comment bool // whether we're in a comment
		quoted  bool // whether we're in a quoted segment
		escaped bool // whether current char is escaped

		heredoc              heredocState // whether we're in a heredoc
		heredocEscaped       bool         // whether heredoc is escaped
		heredocMarker        []rune
		heredocClosingMarker []rune

		nesting int // indentation level
	)

	write := func(ch rune) {
		out.WriteRune(ch)
		last = ch
	}

	indent := func() {
		for tabs := nesting; tabs > 0; tabs-- {
			write('\t')
		}
	}

	nextLine := func() {
		write('\n')
		beginningOfLine = true
	}

	for {
		ch, _, err := rdr.ReadRune()
		if err != nil {
			if err == io.EOF {
				break
			}
			panic(err)
		}

		// detect whether we have the start of a heredoc
		if !quoted && !(heredoc != heredocClosed || heredocEscaped) &&
			space && last == '<' && ch == '<' {
			write(ch)
			heredoc = heredocOpening
			space = false
			continue
		}

		if heredoc == heredocOpening {
			if ch == '\n' {
				if len(heredocMarker) > 0 && heredocMarkerRegexp.MatchString(string(heredocMarker)) {
					heredoc = heredocOpened
				} else {
					heredocMarker = nil
					heredoc = heredocClosed
					nextLine()
					continue
				}
				write(ch)
				continue
			}
			if unicode.IsSpace(ch) {
				// a space means it's just a regular token and not a heredoc
				heredocMarker = nil
				heredoc = heredocClosed
			} else {
				heredocMarker = append(heredocMarker, ch)
				write(ch)
				continue
			}
		}
		// if we're in a heredoc, all characters are read&write as-is
		if heredoc == heredocOpened {
			heredocClosingMarker = append(heredocClosingMarker, ch)
			if len(heredocClosingMarker) > len(heredocMarker)+1 { // We assert that the heredocClosingMarker is followed by a unicode.Space
				heredocClosingMarker = heredocClosingMarker[1:]
			}
			// check if we're done
			if unicode.IsSpace(ch) && slices.Equal(heredocClosingMarker[:len(heredocClosingMarker)-1], heredocMarker) {
				heredocMarker = nil
				heredocClosingMarker = nil
				heredoc = heredocClosed
			} else {
				write(ch)
				if ch == '\n' {
					heredocClosingMarker = heredocClosingMarker[:0]
				}
				continue
			}
		}

		if last == '<' && space {
			space = false
		}

		if comment {
			if ch == '\n' {
				comment = false
				space = true
				nextLine()
				continue
			} else {
				write(ch)
				continue
			}
		}

		if !escaped && ch == '\\' {
			if space {
				write(' ')
				space = false
			}
			write(ch)
			escaped = true
			continue
		}

		if escaped {
			if ch == '<' {
				heredocEscaped = true
			}
			write(ch)
			escaped = false
			continue
		}

		if quoted {
			if ch == '"' {
				quoted = false
			}
			write(ch)
			continue
		}

		if space && ch == '"' {
			quoted = true
		}

		if unicode.IsSpace(ch) {
			space = true
			heredocEscaped = false
			if ch == '\n' {
				newLines++
			}
			continue
		}
		spacePrior := space
		space = false

		//////////////////////////////////////////////////////////
		// I find it helpful to think of the formatting loop in two
		// main sections; by the time we reach this point, we
		// know we are in a "regular" part of the file: we know
		// the character is not a space, not in a literal segment
		// like a comment or quoted, it's not escaped, etc.
		//////////////////////////////////////////////////////////

		if ch == '#' {
			comment = true
		}

		if openBrace && spacePrior && !openBraceWritten {
			if nesting == 0 && last == '}' {
				nextLine()
				nextLine()
			}

			openBrace = false
			if beginningOfLine {
				indent()
			} else if !openBraceSpace {
				write(' ')
			}
			write('{')
			openBraceWritten = true
			nextLine()
			newLines = 0
			// prevent infinite nesting from ridiculous inputs (issue #4169)
			if nesting < 10 {
				nesting++
			}
		}

		switch {
		case ch == '{':
			openBrace = true
			openBraceWritten = false
			openBraceSpace = spacePrior && !beginningOfLine
			if openBraceSpace {
				write(' ')
			}
			continue

		case ch == '}' && (spacePrior || !openBrace):
			if last != '\n' {
				nextLine()
			}
			if nesting > 0 {
				nesting--
			}
			indent()
			write('}')
			newLines = 0
			continue
		}

		if newLines > 2 {
			newLines = 2
		}
		for i := 0; i < newLines; i++ {
			nextLine()
		}
		newLines = 0
		if beginningOfLine {
			indent()
		}
		if nesting == 0 && last == '}' && beginningOfLine {
			nextLine()
			nextLine()
		}

		if !beginningOfLine && spacePrior {
			write(' ')
		}

		if openBrace && !openBraceWritten {
			write('{')
			openBraceWritten = true
		}

		if spacePrior && ch == '<' {
			space = true
		}

		write(ch)

		beginningOfLine = false
	}

	// the Caddyfile does not need any leading or trailing spaces, but...
	trimmedResult := bytes.TrimSpace(out.Bytes())

	// ...Caddyfiles should, however, end with a newline because
	// newlines are significant to the syntax of the file
	return append(trimmedResult, '\n')
}
