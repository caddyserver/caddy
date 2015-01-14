package config

import (
	"errors"
	"fmt"
	"strings"
)

// parser is a type which can parse config files.
type parser struct {
	lexer lexer
	cfg   Config
}

// Parse parses the configuration file. It produces a slice of Config
// structs which can be used to create and configure server instances.
func (p *parser) Parse() ([]Config, error) {
	var configs []Config

	for p.lexer.Next() {
		p.cfg = Config{ErrorPages: make(map[int]string)}

		err := p.parse()
		if err != nil {
			return configs, err
		}

		configs = append(configs, p.cfg)
	}

	return configs, nil
}

// tkn is shorthand to get the text/value of the current token.
func (p *parser) tkn() string {
	return p.lexer.token.text
}

// line is shorthand to get the line number of the current token.
func (p *parser) line() int {
	return p.lexer.token.line
}

// syntaxErr creates a syntax error which explains what was
// found and expected.
func (p *parser) syntaxErr(expected string) error {
	return p.err("Syntax", fmt.Sprintf("Unexpected token '%s', expecting '%s'", p.tkn(), expected))
}

// syntaxErr creates a syntax error that explains that there
// weren't enough arguments on the line.
func (p *parser) argErr() error {
	return p.err("Syntax", "Unexpected line break after '"+p.tkn()+"' (missing arguments?)")
}

// eofErr creates a syntax error describing an unexpected EOF.
func (p *parser) eofErr() error {
	return p.err("Syntax", "Unexpected EOF")
}

// err creates a "{{kind}} error: ..." with a custom message msg. The
// file name and line number are included in the error message.
func (p *parser) err(kind, msg string) error {
	msg = fmt.Sprintf("%s error: %s:%d - %s", kind, p.lexer.file.Name(), p.line(), msg)
	return errors.New(msg)
}

// parseAddress takes a host:port string (val), and returns the host
// and port as separate values. Empty strings can be returned if
// either is missing.
func parseAddress(val string) (string, string) {
	parts := strings.SplitN(val, ":", 3)
	if len(parts) == 1 {
		return parts[0], ""
	} else {
		return parts[0], parts[1]
	}
}
