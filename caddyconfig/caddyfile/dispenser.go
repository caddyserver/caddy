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
	"errors"
	"fmt"
	"io"
	"log"
	"strconv"
	"strings"
)

// Dispenser is a type that dispenses tokens, similarly to a lexer,
// except that it can do so with some notion of structure. An empty
// Dispenser is invalid; call NewDispenser to make a proper instance.
type Dispenser struct {
	tokens  []Token
	cursor  int
	nesting int

	// A map of arbitrary context data that can be used
	// to pass through some information to unmarshalers.
	context map[string]any
}

// NewDispenser returns a Dispenser filled with the given tokens.
func NewDispenser(tokens []Token) *Dispenser {
	return &Dispenser{
		tokens: tokens,
		cursor: -1,
	}
}

// NewTestDispenser parses input into tokens and creates a new
// Dispenser for test purposes only; any errors are fatal.
func NewTestDispenser(input string) *Dispenser {
	tokens, err := allTokens("Testfile", []byte(input))
	if err != nil && err != io.EOF {
		log.Fatalf("getting all tokens from input: %v", err)
	}
	return NewDispenser(tokens)
}

// Next loads the next token. Returns true if a token
// was loaded; false otherwise. If false, all tokens
// have been consumed.
func (d *Dispenser) Next() bool {
	if d.cursor < len(d.tokens)-1 {
		d.cursor++
		return true
	}
	return false
}

// Prev moves to the previous token. It does the inverse
// of Next(), except this function may decrement the cursor
// to -1 so that the next call to Next() points to the
// first token; this allows dispensing to "start over". This
// method returns true if the cursor ends up pointing to a
// valid token.
func (d *Dispenser) Prev() bool {
	if d.cursor > -1 {
		d.cursor--
		return d.cursor > -1
	}
	return false
}

// NextArg loads the next token if it is on the same
// line and if it is not a block opening (open curly
// brace). Returns true if an argument token was
// loaded; false otherwise. If false, all tokens on
// the line have been consumed except for potentially
// a block opening. It handles imported tokens
// correctly.
func (d *Dispenser) NextArg() bool {
	if !d.nextOnSameLine() {
		return false
	}
	if d.Val() == "{" {
		// roll back; a block opening is not an argument
		d.cursor--
		return false
	}
	return true
}

// nextOnSameLine advances the cursor if the next
// token is on the same line of the same file.
func (d *Dispenser) nextOnSameLine() bool {
	if d.cursor < 0 {
		d.cursor++
		return true
	}
	if d.cursor >= len(d.tokens)-1 {
		return false
	}
	curr := d.tokens[d.cursor]
	next := d.tokens[d.cursor+1]
	if !isNextOnNewLine(curr, next) {
		d.cursor++
		return true
	}
	return false
}

// NextLine loads the next token only if it is not on the same
// line as the current token, and returns true if a token was
// loaded; false otherwise. If false, there is not another token
// or it is on the same line. It handles imported tokens correctly.
func (d *Dispenser) NextLine() bool {
	if d.cursor < 0 {
		d.cursor++
		return true
	}
	if d.cursor >= len(d.tokens)-1 {
		return false
	}
	curr := d.tokens[d.cursor]
	next := d.tokens[d.cursor+1]
	if isNextOnNewLine(curr, next) {
		d.cursor++
		return true
	}
	return false
}

// NextBlock can be used as the condition of a for loop
// to load the next token as long as it opens a block or
// is already in a block nested more than initialNestingLevel.
// In other words, a loop over NextBlock() will iterate
// all tokens in the block assuming the next token is an
// open curly brace, until the matching closing brace.
// The open and closing brace tokens for the outer-most
// block will be consumed internally and omitted from
// the iteration.
//
// Proper use of this method looks like this:
//
//	for nesting := d.Nesting(); d.NextBlock(nesting); {
//	}
//
// However, in simple cases where it is known that the
// Dispenser is new and has not already traversed state
// by a loop over NextBlock(), this will do:
//
//	for d.NextBlock(0) {
//	}
//
// As with other token parsing logic, a loop over
// NextBlock() should be contained within a loop over
// Next(), as it is usually prudent to skip the initial
// token.
func (d *Dispenser) NextBlock(initialNestingLevel int) bool {
	if d.nesting > initialNestingLevel {
		if !d.Next() {
			return false // should be EOF error
		}
		if d.Val() == "}" && !d.nextOnSameLine() {
			d.nesting--
		} else if d.Val() == "{" && !d.nextOnSameLine() {
			d.nesting++
		}
		return d.nesting > initialNestingLevel
	}
	if !d.nextOnSameLine() { // block must open on same line
		return false
	}
	if d.Val() != "{" {
		d.cursor-- // roll back if not opening brace
		return false
	}
	d.Next() // consume open curly brace
	if d.Val() == "}" {
		return false // open and then closed right away
	}
	d.nesting++
	return true
}

// Nesting returns the current nesting level. Necessary
// if using NextBlock()
func (d *Dispenser) Nesting() int {
	return d.nesting
}

// Val gets the text of the current token. If there is no token
// loaded, it returns empty string.
func (d *Dispenser) Val() string {
	if d.cursor < 0 || d.cursor >= len(d.tokens) {
		return ""
	}
	return d.tokens[d.cursor].Text
}

// ValRaw gets the raw text of the current token (including quotes).
// If the token was a heredoc, then the delimiter is not included,
// because that is not relevant to any unmarshaling logic at this time.
// If there is no token loaded, it returns empty string.
func (d *Dispenser) ValRaw() string {
	if d.cursor < 0 || d.cursor >= len(d.tokens) {
		return ""
	}
	quote := d.tokens[d.cursor].wasQuoted
	if quote > 0 && quote != '<' {
		// string literal
		return string(quote) + d.tokens[d.cursor].Text + string(quote)
	}
	return d.tokens[d.cursor].Text
}

// ScalarVal gets value of the current token, converted to the closest
// scalar type. If there is no token loaded, it returns nil.
func (d *Dispenser) ScalarVal() any {
	if d.cursor < 0 || d.cursor >= len(d.tokens) {
		return nil
	}
	quote := d.tokens[d.cursor].wasQuoted
	text := d.tokens[d.cursor].Text

	if quote > 0 {
		return text // string literal
	}
	if num, err := strconv.Atoi(text); err == nil {
		return num
	}
	if num, err := strconv.ParseFloat(text, 64); err == nil {
		return num
	}
	if bool, err := strconv.ParseBool(text); err == nil {
		return bool
	}
	return text
}

// Line gets the line number of the current token.
// If there is no token loaded, it returns 0.
func (d *Dispenser) Line() int {
	if d.cursor < 0 || d.cursor >= len(d.tokens) {
		return 0
	}
	return d.tokens[d.cursor].Line
}

// File gets the filename where the current token originated.
func (d *Dispenser) File() string {
	if d.cursor < 0 || d.cursor >= len(d.tokens) {
		return ""
	}
	return d.tokens[d.cursor].File
}

// Args is a convenience function that loads the next arguments
// (tokens on the same line) into an arbitrary number of strings
// pointed to in targets. If there are not enough argument tokens
// available to fill targets, false is returned and the remaining
// targets are left unchanged. If all the targets are filled,
// then true is returned.
func (d *Dispenser) Args(targets ...*string) bool {
	for i := 0; i < len(targets); i++ {
		if !d.NextArg() {
			return false
		}
		*targets[i] = d.Val()
	}
	return true
}

// AllArgs is like Args, but if there are more argument tokens
// available than there are targets, false is returned. The
// number of available argument tokens must match the number of
// targets exactly to return true.
func (d *Dispenser) AllArgs(targets ...*string) bool {
	if !d.Args(targets...) {
		return false
	}
	if d.NextArg() {
		d.Prev()
		return false
	}
	return true
}

// CountRemainingArgs counts the amount of remaining arguments
// (tokens on the same line) without consuming the tokens.
func (d *Dispenser) CountRemainingArgs() int {
	count := 0
	for d.NextArg() {
		count++
	}
	for i := 0; i < count; i++ {
		d.Prev()
	}
	return count
}

// RemainingArgs loads any more arguments (tokens on the same line)
// into a slice and returns them. Open curly brace tokens also indicate
// the end of arguments, and the curly brace is not included in
// the return value nor is it loaded.
func (d *Dispenser) RemainingArgs() []string {
	var args []string
	for d.NextArg() {
		args = append(args, d.Val())
	}
	return args
}

// RemainingArgsRaw loads any more arguments (tokens on the same line,
// retaining quotes) into a slice and returns them. Open curly brace
// tokens also indicate the end of arguments, and the curly brace is
// not included in the return value nor is it loaded.
func (d *Dispenser) RemainingArgsRaw() []string {
	var args []string
	for d.NextArg() {
		args = append(args, d.ValRaw())
	}
	return args
}

// NewFromNextSegment returns a new dispenser with a copy of
// the tokens from the current token until the end of the
// "directive" whether that be to the end of the line or
// the end of a block that starts at the end of the line;
// in other words, until the end of the segment.
func (d *Dispenser) NewFromNextSegment() *Dispenser {
	return NewDispenser(d.NextSegment())
}

// NextSegment returns a copy of the tokens from the current
// token until the end of the line or block that starts at
// the end of the line.
func (d *Dispenser) NextSegment() Segment {
	tkns := Segment{d.Token()}
	for d.NextArg() {
		tkns = append(tkns, d.Token())
	}
	var openedBlock bool
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		if !openedBlock {
			// because NextBlock() consumes the initial open
			// curly brace, we rewind here to append it, since
			// our case is special in that we want the new
			// dispenser to have all the tokens including
			// surrounding curly braces
			d.Prev()
			tkns = append(tkns, d.Token())
			d.Next()
			openedBlock = true
		}
		tkns = append(tkns, d.Token())
	}
	if openedBlock {
		// include closing brace
		tkns = append(tkns, d.Token())

		// do not consume the closing curly brace; the
		// next iteration of the enclosing loop will
		// call Next() and consume it
	}
	return tkns
}

// Token returns the current token.
func (d *Dispenser) Token() Token {
	if d.cursor < 0 || d.cursor >= len(d.tokens) {
		return Token{}
	}
	return d.tokens[d.cursor]
}

// Reset sets d's cursor to the beginning, as
// if this was a new and unused dispenser.
func (d *Dispenser) Reset() {
	d.cursor = -1
	d.nesting = 0
}

// ArgErr returns an argument error, meaning that another
// argument was expected but not found. In other words,
// a line break or open curly brace was encountered instead of
// an argument.
func (d *Dispenser) ArgErr() error {
	if d.Val() == "{" {
		return d.Err("unexpected token '{', expecting argument")
	}
	return d.Errf("wrong argument count or unexpected line ending after '%s'", d.Val())
}

// SyntaxErr creates a generic syntax error which explains what was
// found and what was expected.
func (d *Dispenser) SyntaxErr(expected string) error {
	msg := fmt.Sprintf("syntax error: unexpected token '%s', expecting '%s', at %s:%d import chain: ['%s']", d.Val(), expected, d.File(), d.Line(), strings.Join(d.Token().imports, "','"))
	return errors.New(msg)
}

// EOFErr returns an error indicating that the dispenser reached
// the end of the input when searching for the next token.
func (d *Dispenser) EOFErr() error {
	return d.Errf("unexpected EOF")
}

// Err generates a custom parse-time error with a message of msg.
func (d *Dispenser) Err(msg string) error {
	return d.WrapErr(errors.New(msg))
}

// Errf is like Err, but for formatted error messages
func (d *Dispenser) Errf(format string, args ...any) error {
	return d.WrapErr(fmt.Errorf(format, args...))
}

// WrapErr takes an existing error and adds the Caddyfile file and line number.
func (d *Dispenser) WrapErr(err error) error {
	if len(d.Token().imports) > 0 {
		return fmt.Errorf("%w, at %s:%d import chain ['%s']", err, d.File(), d.Line(), strings.Join(d.Token().imports, "','"))
	}
	return fmt.Errorf("%w, at %s:%d", err, d.File(), d.Line())
}

// Delete deletes the current token and returns the updated slice
// of tokens. The cursor is not advanced to the next token.
// Because deletion modifies the underlying slice, this method
// should only be called if you have access to the original slice
// of tokens and/or are using the slice of tokens outside this
// Dispenser instance. If you do not re-assign the slice with the
// return value of this method, inconsistencies in the token
// array will become apparent (or worse, hide from you like they
// did me for 3 and a half freaking hours late one night).
func (d *Dispenser) Delete() []Token {
	if d.cursor >= 0 && d.cursor <= len(d.tokens)-1 {
		d.tokens = append(d.tokens[:d.cursor], d.tokens[d.cursor+1:]...)
		d.cursor--
	}
	return d.tokens
}

// DeleteN is the same as Delete, but can delete many tokens at once.
// If there aren't N tokens available to delete, none are deleted.
func (d *Dispenser) DeleteN(amount int) []Token {
	if amount > 0 && d.cursor >= (amount-1) && d.cursor <= len(d.tokens)-1 {
		d.tokens = append(d.tokens[:d.cursor-(amount-1)], d.tokens[d.cursor+1:]...)
		d.cursor -= amount
	}
	return d.tokens
}

// SetContext sets a key-value pair in the context map.
func (d *Dispenser) SetContext(key string, value any) {
	if d.context == nil {
		d.context = make(map[string]any)
	}
	d.context[key] = value
}

// GetContext gets the value of a key in the context map.
func (d *Dispenser) GetContext(key string) any {
	if d.context == nil {
		return nil
	}
	return d.context[key]
}

// GetContextString gets the value of a key in the context map
// as a string, or an empty string if the key does not exist.
func (d *Dispenser) GetContextString(key string) string {
	if d.context == nil {
		return ""
	}
	if val, ok := d.context[key].(string); ok {
		return val
	}
	return ""
}

// isNewLine determines whether the current token is on a different
// line (higher line number) than the previous token. It handles imported
// tokens correctly. If there isn't a previous token, it returns true.
func (d *Dispenser) isNewLine() bool {
	if d.cursor < 1 {
		return true
	}
	if d.cursor > len(d.tokens)-1 {
		return false
	}

	prev := d.tokens[d.cursor-1]
	curr := d.tokens[d.cursor]
	return isNextOnNewLine(prev, curr)
}

// isNextOnNewLine determines whether the current token is on a different
// line (higher line number) than the next token. It handles imported
// tokens correctly. If there isn't a next token, it returns true.
func (d *Dispenser) isNextOnNewLine() bool {
	if d.cursor < 0 {
		return false
	}
	if d.cursor >= len(d.tokens)-1 {
		return true
	}

	curr := d.tokens[d.cursor]
	next := d.tokens[d.cursor+1]
	return isNextOnNewLine(curr, next)
}

const MatcherNameCtxKey = "matcher_name"
