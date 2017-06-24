package caddyfile

import (
	"bufio"
	"io"
	"unicode"
)

type (
	// lexer is a utility which can get values, token by
	// token, from a Reader. A token is a word, and tokens
	// are separated by whitespace. A word can be enclosed
	// in quotes if it contains whitespace.
	lexer struct {
		reader *bufio.Reader
		token  Token
		line   int
	}

	// Token represents a single parsable unit.
	Token struct {
		File string
		Line int
		Text string
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
	var comment, quoted, escaped bool

	makeToken := func() bool {
		l.token.Text = string(val)
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
			}
			panic(err)
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
			if ch == '\n' {
				l.line++
			}
			if escaped {
				// only escape quotes
				if ch != '"' {
					val = append(val, '\\')
				}
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
			l.token = Token{Line: l.line}
			if ch == '"' {
				quoted = true
				continue
			}
		}

		val = append(val, ch)
	}
}
