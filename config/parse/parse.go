// Package parse provides facilities for parsing configuration files.
package parse

import "io"

// ServerBlocks parses the input just enough to organize tokens,
// in order, by server block. No further parsing is performed.
// Server blocks are returned in the order in which they appear.
func ServerBlocks(filename string, input io.Reader) ([]ServerBlock, error) {
	p := parser{Dispenser: NewDispenser(filename, input)}
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

// Set of directives that are valid (unordered). Populated
// by config package's init function.
var ValidDirectives = make(map[string]struct{})
