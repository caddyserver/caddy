package config

import (
	"errors"
	"net"
	"strings"
)

// This file contains the recursive-descent parsing
// functions.

// begin is the top of the recursive-descent parsing.
// It parses at most one server configuration (an address
// and its directives).
func (p *parser) begin() error {
	err := p.addresses()
	if err != nil {
		return err
	}

	err = p.addressBlock()
	if err != nil {
		return err
	}

	return nil
}

// addresses expects that the current token is a
// "scheme://host:port" combination (the "scheme://"
// and/or ":port" portions may be omitted). If multiple
// addresses are specified, they must be space-
// separated on the same line, or each token must end
// with a comma.
func (p *parser) addresses() error {
	var expectingAnother bool
	p.hosts = []hostPort{}

	// address gets host and port in a format accepted by net.Dial
	address := func(str string) (host, port string, err error) {
		if strings.HasPrefix(str, "https://") {
			port = "https"
			host = str[8:]
			return
		} else if strings.HasPrefix(str, "http://") {
			port = "http"
			host = str[7:]
			return
		} else if !strings.Contains(str, ":") {
			str += ":" + defaultPort
		}
		host, port, err = net.SplitHostPort(str)
		return
	}

	for {
		tkn, startLine := p.tkn(), p.line()

		// Open brace definitely indicates end of addresses
		if tkn == "{" {
			if expectingAnother {
				return p.err("Syntax", "Expected another address but had '"+tkn+"' - check for extra comma")
			}
			break
		}

		// Trailing comma indicates another address will follow, which
		// may possibly be on the next line
		if tkn[len(tkn)-1] == ',' {
			tkn = tkn[:len(tkn)-1]
			expectingAnother = true
		} else {
			expectingAnother = false // but we may still see another one on this line
		}

		// Parse and save this address
		host, port, err := address(tkn)
		if err != nil {
			return err
		}
		p.hosts = append(p.hosts, hostPort{host, port})

		// Advance token and possibly break out of loop or return error
		hasNext := p.next()
		if expectingAnother && !hasNext {
			return p.eofErr()
		}
		if !expectingAnother && p.line() > startLine {
			break
		}
	}

	return nil
}

// addressBlock leads into parsing directives, including
// possible opening/closing curly braces around the block.
// It handles directives enclosed by curly braces and
// directives not enclosed by curly braces. It is expected
// that the current token is already the beginning of
// the address block.
func (p *parser) addressBlock() error {
	errOpenCurlyBrace := p.openCurlyBrace()
	if errOpenCurlyBrace != nil {
		// meh, single-server configs don't need curly braces
		// but we read a token and we won't consume it; mark it unused
		p.unused = &p.lexer.token
	}

	// When we enter an address block, we also implicitly
	// enter a path block where the path is all paths ("/")
	p.other = append(p.other, locationContext{
		path:       "/",
		directives: make(map[string]*controller),
	})
	p.scope = &p.other[0]

	err := p.directives()
	if err != nil {
		return err
	}

	// Only look for close curly brace if there was an opening
	if errOpenCurlyBrace == nil {
		err = p.closeCurlyBrace()
		if err != nil {
			return err
		}
	}

	return nil
}

// openCurlyBrace expects the current token to be an
// opening curly brace. This acts like an assertion
// because it returns an error if the token is not
// a opening curly brace. It does not advance the token.
func (p *parser) openCurlyBrace() error {
	if p.tkn() != "{" {
		return p.syntaxErr("{")
	}
	return nil
}

// closeCurlyBrace expects the current token to be
// a closing curly brace. This acts like an assertion
// because it returns an error if the token is not
// a closing curly brace. It does not advance the token.
func (p *parser) closeCurlyBrace() error {
	if p.tkn() != "}" {
		return p.syntaxErr("}")
	}
	return nil
}

// directives parses through all the directives
// and it expects the current token to be the first
// directive. It goes until EOF or closing curly
// brace which ends the address block.
func (p *parser) directives() error {
	for p.next() {
		if p.tkn() == "}" {
			// end of address scope
			break
		}
		if p.tkn()[0] == '/' || p.tkn()[0] == '*' {
			// Path scope (a.k.a. location context)
			// Starts with / ('starts with') or * ('ends with').

			// TODO: The parser can handle the syntax (obviously), but the
			// implementation is incomplete. This is intentional,
			// until we can better decide what kind of feature set we
			// want to support and how exactly we want these location
			// scopes to work. Until this is ready, we leave this
			// syntax undocumented. Some changes will need to be
			// made in parser.go also (the unwrap function) and
			// probably in server.go when we do this... see those TODOs.

			var scope *locationContext

			// If the path block is a duplicate, append to existing one
			for i := 0; i < len(p.other); i++ {
				if p.other[i].path == p.tkn() {
					scope = &p.other[i]
					break
				}
			}

			// Otherwise, for a new path we haven't seen before, create a new context
			if scope == nil {
				scope = &locationContext{
					path:       p.tkn(),
					directives: make(map[string]*controller),
				}
			}

			// Consume the opening curly brace
			if !p.next() {
				return p.eofErr()
			}
			err := p.openCurlyBrace()
			if err != nil {
				return err
			}

			// Use this path scope as our current context for just a moment
			p.scope = scope

			// Consume each directive in the path block
			for p.next() {
				err := p.closeCurlyBrace()
				if err == nil {
					break
				}

				err = p.directive()
				if err != nil {
					return err
				}
			}

			// Save the new scope and put the current scope back to "/"
			p.other = append(p.other, *scope)
			p.scope = &p.other[0]

		} else if err := p.directive(); err != nil {
			return err
		}
	}
	return nil
}

// directive asserts that the current token is either a built-in
// directive or a registered middleware directive; otherwise an error
// will be returned. If it is a valid directive, tokens will be
// collected.
func (p *parser) directive() error {
	if fn, ok := validDirectives[p.tkn()]; ok {
		// Built-in (standard, or 'core') directive
		err := fn(p)
		if err != nil {
			return err
		}
	} else if middlewareRegistered(p.tkn()) {
		// Middleware directive
		err := p.collectTokens()
		if err != nil {
			return err
		}
	} else {
		return p.err("Syntax", "Unexpected token '"+p.tkn()+"', expecting a valid directive")
	}
	return nil
}

// collectTokens consumes tokens until the directive's scope
// closes (either end of line or end of curly brace block).
// It creates a controller which is stored in the parser for
// later use by the middleware.
func (p *parser) collectTokens() error {
	if p.scope == nil {
		return errors.New("Current scope cannot be nil")
	}

	directive := p.tkn()
	line := p.line()
	nesting := 0
	cont := newController(p)

	// Re-use a duplicate directive's controller from before
	// (the parsing logic in the middleware generator must
	// account for multiple occurrences of its directive, even
	// if that means returning an error or overwriting settings)
	if existing, ok := p.scope.directives[directive]; ok {
		cont = existing
	}

	// The directive is appended as a relevant token
	cont.tokens = append(cont.tokens, p.lexer.token)

	for p.next() {
		if p.tkn() == "{" {
			nesting++
		} else if p.line() > line && nesting == 0 {
			p.unused = &p.lexer.token
			break
		} else if p.tkn() == "}" && nesting > 0 {
			nesting--
		} else if p.tkn() == "}" && nesting == 0 {
			return p.err("Syntax", "Unexpected '}' because no matching opening brace")
		}
		cont.tokens = append(cont.tokens, p.lexer.token)
	}

	if nesting > 0 {
		return p.eofErr()
	}

	p.scope.directives[directive] = cont
	return nil
}
