package config

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/mholt/caddy/middleware"
)

type (
	// parser is a type which can parse config files.
	parser struct {
		filename string            // the name of the file that we're parsing
		lexer    lexer             // the lexer that is giving us tokens from the raw input
		cfg      Config            // each server gets one Config; this is the one we're currently building
		other    []locationContext // tokens to be 'parsed' later by middleware generators
		scope    *locationContext  // the current location context (path scope) being populated
		unused   bool              // sometimes a token will be read but not immediately consumed
	}

	// locationContext represents a location context
	// (path block) in a config file. If no context
	// is explicitly defined, the default location
	// context is "/".
	locationContext struct {
		path       string
		directives map[string]*controller
	}
)

// newParser makes a new parser and prepares it for parsing, given
// the input to parse.
func newParser(file *os.File) (*parser, error) {
	stat, err := file.Stat()
	if err != nil {
		return nil, err
	}

	p := &parser{filename: stat.Name()}
	p.lexer.load(file)

	return p, nil
}

// Parse parses the configuration file. It produces a slice of Config
// structs which can be used to create and configure server instances.
func (p *parser) parse() ([]Config, error) {
	var configs []Config

	for p.lexer.next() {
		err := p.parseOne()
		if err != nil {
			return nil, err
		}
		configs = append(configs, p.cfg)
	}

	return configs, nil
}

// nextArg loads the next token if it is on the same line.
// Returns true if a token was loaded; false otherwise.
func (p *parser) nextArg() bool {
	if p.unused {
		return false
	}
	line := p.line()
	if p.next() {
		if p.line() > line {
			p.unused = true
			return false
		}
		return true
	}
	return false
}

// next loads the next token and returns true if a token
// was loaded; false otherwise.
func (p *parser) next() bool {
	if p.unused {
		p.unused = false
		return true
	} else {
		return p.lexer.next()
	}
}

// parseOne parses the contents of a configuration
// file for a single Config object (each server or
// virtualhost instance gets their own Config struct),
// which is until the next address/server block.
// Call this only when you know that the lexer has another
// another token and you're not in another server
// block already.
func (p *parser) parseOne() error {
	p.cfg = Config{
		Middleware: make(map[string][]middleware.Middleware),
	}
	p.other = []locationContext{}

	err := p.begin()
	if err != nil {
		return err
	}

	err = p.unwrap()
	if err != nil {
		return err
	}

	return nil
}

// unwrap gets the middleware generators from the middleware
// package in the order in which they are registered, and
// executes the top-level functions (the generator function)
// to expose the second layers which are the actual middleware.
// This function should be called only after p has filled out
// p.other and the entire server block has already been consumed.
func (p *parser) unwrap() error {
	if len(p.other) == 0 {
		// no middlewares were invoked
		return nil
	}

	for _, directive := range registry.ordered {
		// TODO: For now, we only support the first and default path scope ("/", held in p.other[0])
		// but when we implement support for path scopes, we will have to change this logic
		// to loop over them and order them. We need to account for situations where multiple
		// path scopes overlap, regex (??), etc...
		if disp, ok := p.other[0].directives[directive]; ok {
			if generator, ok := registry.directiveMap[directive]; ok {
				mid, err := generator(disp)
				if err != nil {
					return err
				}
				if mid != nil {
					// TODO: Again, we assume the default path scope here...
					p.cfg.Middleware[p.other[0].path] = append(p.cfg.Middleware[p.other[0].path], mid)
				}
			} else {
				return errors.New("No middleware bound to directive '" + directive + "'")
			}
		}
	}

	return nil
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

// err creates an error with a custom message msg: "{{kind}} error: {{msg}}". The
// file name and line number are included in the error message.
func (p *parser) err(kind, msg string) error {
	msg = fmt.Sprintf("%s:%d - %s error: %s", p.filename, p.line(), kind, msg)
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
