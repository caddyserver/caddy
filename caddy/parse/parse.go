// Package parse provides facilities for parsing configuration files.
package parse

import "io"

// ServerBlocks parses the input just enough to organize tokens,
// in order, by server block. No further parsing is performed.
// If checkDirectives is true, only valid directives will be allowed
// otherwise we consider it a parse error. Server blocks are returned
// in the order in which they appear.
func ServerBlocks(filename string, input io.Reader, checkDirectives bool) ([]ServerBlock, error) {
	p := parser{Dispenser: NewDispenser(filename, input)}
	p.checkDirectives = checkDirectives
	blocks, err := p.parseAll()
	return blocks, err
}

// allTokens lexes the entire input, but does not parse it.
// It returns all the tokens from the input, unstructured
// and in order.
func allTokens(input io.Reader) (tokens []token) {
	l := new(lexer)
	l.load(input)
	for l.next() {
		tokens = append(tokens, l.token)
	}
	return
}

// ValidDirectives is a set of directives that are valid (unordered). Populated
// by config package's init function.
var ValidDirectives = make(map[string]struct{})
