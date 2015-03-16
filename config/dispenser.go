package config

import (
	"errors"
	"fmt"
)

// dispenser is a type that gets exposed to middleware
// generators so that they can parse tokens to configure
// their instance. It basically dispenses tokens but can
// do so in a structured manner.
type dispenser struct {
	filename string
	cursor   int
	nesting  int
	tokens   []token
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
// brace is consumed by this method. Usually, you would
// use this as the condition of a for loop to parse
// tokens while being inside the block.
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

// ArgErr returns an argument error, meaning that another
// argument was expected but not found. In other words,
// a line break or open curly brace was encountered instead of
// an argument.
func (d *dispenser) ArgErr() error {
	if d.Val() == "{" {
		return d.Err("Unexpected token '{', expecting argument")
	}
	return d.Err("Unexpected line break after '" + d.Val() + "' (missing arguments?)")
}

// Err generates a custom parse error with a message of msg.
func (d *dispenser) Err(msg string) error {
	msg = fmt.Sprintf("%s:%d - Parse error: %s", d.filename, d.tokens[d.cursor].line, msg)
	return errors.New(msg)
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

// RemainingArgs is a convenience function that loads any more arguments
// (tokens on the same line) into a slice and returns them. Open curly
// brace tokens indicate the end of arguments (the curly brace is not
// included).
func (d *dispenser) RemainingArgs() []string {
	var args []string

	for d.NextArg() {
		if d.Val() == "{" {
			d.cursor--
			break
		}
		args = append(args, d.Val())
	}

	return args
}
