package config

// This file contains the recursive-descent parsing
// functions.

// parse is the top of the recursive-descent parsing.
// It parses at most 1 server configuration (an address
// and its directives).
func (p *parser) parse() error {
	err := p.address()
	if err != nil {
		return err
	}

	err = p.addressBlock()
	if err != nil {
		return err
	}

	return nil
}

// address expects that the current token is a host:port
// combination.
func (p *parser) address() error {
	p.cfg.Host, p.cfg.Port = parseAddress(p.tkn())
	p.lexer.Next()
	return nil
}

// addressBlock leads into parsing directives. It
// handles directives enclosed by curly braces and
// directives not enclosed by curly braces.
func (p *parser) addressBlock() error {
	err := p.openCurlyBrace()
	if err != nil {
		// meh, single-server configs don't need curly braces
		return p.directives()
	}

	err = p.directives()
	if err != nil {
		return err
	}

	err = p.closeCurlyBrace()
	if err != nil {
		return err
	}
	return nil
}

// openCurlyBrace expects the current token to be an
// opening curly brace.
func (p *parser) openCurlyBrace() error {
	if p.tkn() != "{" {
		return p.syntaxErr("{")
	}
	return nil
}

// closeCurlyBrace expects the current token to be
// a closing curly brace.
func (p *parser) closeCurlyBrace() error {
	if p.tkn() != "}" {
		return p.syntaxErr("}")
	}
	return nil
}

// directives parses through all the directives
// and it expects the current token to be the first
// directive. It goes until EOF or closing curly
// brace.
func (p *parser) directives() error {
	for p.lexer.Next() {
		if p.tkn() == "}" {
			break
		}
		if fn, ok := validDirectives[p.tkn()]; !ok {
			return p.syntaxErr("[directive]")
		} else {
			err := fn(p)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
