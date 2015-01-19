package config

import (
	"bufio"
	"io"
	"unicode"
)

// lexer is a utility which can get values, token by
// token, from a reader. A token is a word, and tokens
// are separated by whitespace. A word can be enclosed in
// quotes if it contains whitespace.
type lexer struct {
	reader *bufio.Reader
	token  token
	line   int
}

// load prepares the lexer to scan a file for tokens.
func (l *lexer) load(file io.Reader) error {
	l.reader = bufio.NewReader(file)
	l.line = 1
	return nil
}

// next loads the next token into the lexer.
// A token is delimited by whitespace, unless
// the token starts with a quotes character (")
// in which case the token goes until the closing
// quotes (the enclosing quotes are not included).
// The rest of the line is skipped if a "#"
// character is read in. Returns true if a token
// was loaded; false otherwise.
func (l *lexer) next() bool {
	var val []rune
	var comment, quoted, escaped bool

	makeToken := func() bool {
		l.token.text = string(val)
		return true
	}

	for {
		ch, _, err := l.reader.ReadRune()
		if err != nil {
			if len(val) > 0 {
				return makeToken()
			}
			if err == io.EOF {
				return false
			} else {
				panic(err)
			}
		}

		if quoted {
			if !escaped {
				if ch == '\\' {
					escaped = true
					continue
				} else if ch == '"' {
					quoted = false
					return makeToken()
				}
			}
			if ch == '\\' && !escaped {
				escaped = true
				continue
			}
			if ch == '\n' {
				l.line++
			}
			val = append(val, ch)
			escaped = false
			continue
		}

		if unicode.IsSpace(ch) {
			if ch == '\r' {
				continue
			}
			if ch == '\n' {
				l.line++
				comment = false
			}
			if len(val) > 0 {
				return makeToken()
			}
			continue
		}

		if ch == '#' {
			comment = true
		}

		if comment {
			continue
		}

		if len(val) == 0 {
			l.token = token{line: l.line}
			if ch == '"' {
				quoted = true
				continue
			}
		}

		val = append(val, ch)
	}
}

// token represents a single processable unit.
type token struct {
	line int
	text string
}
