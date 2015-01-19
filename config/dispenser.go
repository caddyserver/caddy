package config

import (
	"errors"
	"fmt"

	"github.com/mholt/caddy/middleware"
)

// dispenser is a type that gets exposed to middleware
// generators so that they can parse tokens to configure
// their instance.
type dispenser struct {
	parser *parser
	iter   int
	tokens []token
	err    error
}

// newDispenser returns a new dispenser.
func newDispenser(p *parser) *dispenser {
	d := new(dispenser)
	d.iter = -1
	d.parser = p
	return d
}

// Next loads the next token. Returns true if a token
// was loaded; false otherwise. If false, all tokens
// have been consumed.
// TODO: Have the other Next functions call this one...?
func (d *dispenser) Next() bool {
	if d.iter >= len(d.tokens)-1 {
		return false
	} else {
		d.iter++
		return true
	}
}

// NextArg loads the next token if it is on the same
// line. Returns true if a token was loaded; false
// otherwise. If false, all tokens on the line have
// been consumed.
func (d *dispenser) NextArg() bool {
	if d.iter < 0 {
		d.iter++
		return true
	}
	if d.iter >= len(d.tokens) {
		return false
	}
	if d.iter < len(d.tokens)-1 &&
		d.tokens[d.iter].line == d.tokens[d.iter+1].line {
		d.iter++
		return true
	}
	return false
}

// TODO: Keep this method? It's like NextArg
// but only gets the next token if it's on the next line...
func (d *dispenser) NextLine() bool {
	if d.iter < 0 {
		d.iter++
		return true
	}
	if d.iter >= len(d.tokens) {
		return false
	}
	if d.iter < len(d.tokens)-1 &&
		d.tokens[d.iter].line < d.tokens[d.iter+1].line {
		d.iter++
		return true
	}
	return false
}

// OpenCurlyBrace asserts that the current token is
// an opening curly brace "{". If it isn't, an error
// is produced and false is returned.
func (d *dispenser) OpenCurlyBrace() bool {
	if d.Val() == "{" {
		return true
	} else {
		d.Err("Parse", "Expected '{'")
		return false
	}
}

// CloseCurlyBrace asserts that the current token is
// a closing curly brace "}". If it isn't, an error
// is produced and false is returned.
func (d *dispenser) CloseCurlyBrace() bool {
	if d.Val() == "}" {
		return true
	} else {
		d.Err("Parse", "Expected '}'")
		return false
	}
}

// Val gets the text of the current token.
func (d *dispenser) Val() string {
	if d.iter >= len(d.tokens) || d.iter < 0 {
		return ""
	} else {
		return d.tokens[d.iter].text
	}
}

// ArgErr generates an argument error, meaning that another
// argument was expected but not found. The error is saved
// within the dispenser, but this function returns nil for
// convenience.
func (d *dispenser) ArgErr() middleware.Middleware {
	if d.Val() == "{" {
		d.Err("Syntax", "Unexpected token '{', expecting argument for directive")
		return nil
	}
	d.Err("Syntax", "Unexpected line break after '"+d.tokens[d.iter].text+"' (missing arguments?)")
	return nil
}

// Err generates a custom error of type kind and with a message
// of msg. The kind should be capitalized. This function returns
// nil for convenience, but loads the error into the dispenser
// so it can be reported immediately.
func (d *dispenser) Err(kind, msg string) middleware.Middleware {
	msg = fmt.Sprintf("%s:%d - %s error: %s", d.parser.filename, d.tokens[d.iter].line, kind, msg)
	d.err = errors.New(msg)
	return nil
}

// Args is a convenience function that loads the next arguments
// (tokens on the same line) into an arbitrary number of strings
// pointed to in targets. If there are fewer tokens available
// than string pointers, the remaining strings will not be changed.
func (d *dispenser) Args(targets ...*string) {
	i := 0
	for d.NextArg() {
		*targets[i] = d.Val()
		i++
	}
}

// Startup registers a function to execute when the server starts.
func (d *dispenser) Startup(fn func() error) {
	d.parser.cfg.Startup = append(d.parser.cfg.Startup, fn)
}

// Root returns the server root file path.
func (d *dispenser) Root() string {
	if d.parser.cfg.Root == "" {
		return "."
	} else {
		return d.parser.cfg.Root
	}
}

// Host returns the hostname the server is bound to.
func (d *dispenser) Host() string {
	return d.parser.cfg.Host
}

// Port returns the port that the server is listening on.
func (d *dispenser) Port() string {
	return d.parser.cfg.Port
}
