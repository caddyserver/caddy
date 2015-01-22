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
	parser  *parser
	cursor  int
	nesting int
	tokens  []token
	err     error
}

// newDispenser returns a new dispenser.
func newDispenser(p *parser) *dispenser {
	d := new(dispenser)
	d.cursor = -1
	d.parser = p
	return d
}

// Next loads the next token. Returns true if a token
// was loaded; false otherwise. If false, all tokens
// have been consumed.
// TODO: Have the other Next functions call this one...?
func (d *dispenser) Next() bool {
	if d.cursor >= len(d.tokens)-1 {
		return false
	} else {
		d.cursor++
		return true
	}
}

// NextArg loads the next token if it is on the same
// line. Returns true if a token was loaded; false
// otherwise. If false, all tokens on the line have
// been consumed.
func (d *dispenser) NextArg() bool {
	if d.cursor < 0 {
		d.cursor++
		return true
	}
	if d.cursor >= len(d.tokens) {
		return false
	}
	if d.cursor < len(d.tokens)-1 &&
		d.tokens[d.cursor].line == d.tokens[d.cursor+1].line {
		d.cursor++
		return true
	}
	return false
}

// TODO: Assert that there's a line break and only advance
// the token if that's the case? (store an error otherwise)
func (d *dispenser) NextLine() bool {
	if d.cursor < 0 {
		d.cursor++
		return true
	}
	if d.cursor >= len(d.tokens) {
		return false
	}
	if d.cursor < len(d.tokens)-1 &&
		d.tokens[d.cursor].line < d.tokens[d.cursor+1].line {
		d.cursor++
		return true
	}
	return false
}

// NextBlock advances the cursor to the next token only
// if the current token is an open curly brace on the
// same line. If so, that token is consumed and this
// function will return true until the closing curly
// brace is consumed by this method.
func (d *dispenser) NextBlock() bool {
	if d.nesting > 0 {
		d.Next()
		if d.Val() == "}" {
			d.nesting--
			d.Next() // consume closing brace
			return false
		}
		return true
	}
	if !d.NextArg() {
		return false
	}
	if d.Val() != "{" {
		d.cursor-- // roll back if not opening brace
		return false
	}
	d.Next()
	d.nesting++
	return true
}

// Val gets the text of the current token.
func (d *dispenser) Val() string {
	if d.cursor < 0 || d.cursor >= len(d.tokens) {
		return ""
	} else {
		return d.tokens[d.cursor].text
	}
}

// ArgErr generates an argument error, meaning that another
// argument was expected but not found. The error is saved
// within the dispenser, but this function returns nil for
// convenience in practice.
func (d *dispenser) ArgErr() middleware.Middleware {
	if d.Val() == "{" {
		d.Err("Unexpected token '{', expecting argument")
		return nil
	}
	d.Err("Unexpected line break after '" + d.Val() + "' (missing arguments?)")
	return nil
}

// Err generates a custom parse error with a message of msg.
// This function returns nil for convenience, but loads the
// error into the dispenser so it can be reported. The caller
// of the middleware preparator is responsible for checking
// the error in the dispenser after the middleware preparator
// is finished.
func (d *dispenser) Err(msg string) middleware.Middleware {
	msg = fmt.Sprintf("%s:%d - Parse error: %s", d.parser.filename, d.tokens[d.cursor].line, msg)
	d.err = errors.New(msg)
	return nil
}

// Args is a convenience function that loads the next arguments
// (tokens on the same line) into an arbitrary number of strings
// pointed to in targets. If there are fewer tokens available
// than string pointers, the remaining strings will not be changed
// and false will be returned. If there were enough tokens available
// to fill the arguments, then true will be returned.
func (d *dispenser) Args(targets ...*string) bool {
	enough := true
	for i := 0; i < len(targets); i++ {
		if !d.NextArg() {
			enough = false
			break
		}
		*targets[i] = d.Val()
	}
	return enough
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
