package config

import (
	"bufio"
	"io"
	"os"
	"unicode"
)

// Lexer is a utility which can get values, token by
// token, from a config file. A token is a word, and tokens
// are separated by whitespace. A word can be enclosed in
// quotes if it contains whitespace.
type lexer struct {
	file   *os.File
	reader *bufio.Reader
	token  token
	line   int
}

// Load opens a file and prepares to scan the file.
func (l *lexer) Load(filename string) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	l.reader = bufio.NewReader(f)
	l.file = f
	l.line = 1
	return nil
}

// Close closes the file.
func (l *lexer) Close() {
	l.file.Close()
}

// Next gets the next token from the input. The resulting token
// is in l.token if next returns true. If Next returns false,
// there are no more tokens.
func (l *lexer) Next() bool {
	return l.next(true)
}

// NextArg works just like Next, but returns false if the next
// token is not on the same line as the one before. This method
// makes it easier to throw syntax errors when more values are
// expected on the same line.
func (l *lexer) NextArg() bool {
	return l.next(false)
}

// next gets the next token according to newlineOK, which
// specifies whether it's OK if the next token is on another
// line. Returns true if there was a new token loaded, false
// otherwise.
func (l *lexer) next(newlineOK bool) bool {
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
			if ch == '\n' {
				l.line++
				comment = false
			}
			if len(val) > 0 {
				return makeToken()
			} else if !newlineOK {
				err := l.reader.UnreadRune()
				if err != nil {
					panic(err)
				}
				if ch == '\n' {
					l.line--
				}
				return false
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

// A token represents a single valuable/processable unit
// in a config file.
type token struct {
	line int
	text string
}
