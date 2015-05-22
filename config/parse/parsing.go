package parse

import (
	"net"
	"os"
	"strings"
)

type parser struct {
	Dispenser
	block multiServerBlock // current server block being parsed
	eof   bool             // if we encounter a valid EOF in a hard place
}

func (p *parser) parseAll() ([]serverBlock, error) {
	var blocks []serverBlock

	for p.Next() {
		err := p.parseOne()
		if err != nil {
			return blocks, err
		}

		// explode the multiServerBlock into multiple serverBlocks
		for _, addr := range p.block.addresses {
			blocks = append(blocks, serverBlock{
				Host:   addr.host,
				Port:   addr.port,
				Tokens: p.block.tokens,
			})
		}
	}

	return blocks, nil
}

func (p *parser) parseOne() error {
	p.block = multiServerBlock{tokens: make(map[string][]token)}

	err := p.begin()
	if err != nil {
		return err
	}

	return nil
}

func (p *parser) begin() error {
	if len(p.tokens) == 0 {
		return nil
	}

	err := p.addresses()
	if err != nil {
		return err
	}

	if p.eof {
		// this happens if the Caddyfile consists of only
		// a line of addresses and nothing else
		return nil
	}

	err = p.blockContents()
	if err != nil {
		return err
	}

	return nil
}

func (p *parser) addresses() error {
	var expectingAnother bool

	for {
		tkn, startLine := p.Val(), p.Line()

		// Open brace definitely indicates end of addresses
		if tkn == "{" {
			if expectingAnother {
				return p.Errf("Expected another address but had '%s' - check for extra comma", tkn)
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
		host, port, err := standardAddress(tkn)
		if err != nil {
			return err
		}
		p.block.addresses = append(p.block.addresses, address{host, port})

		// Advance token and possibly break out of loop or return error
		hasNext := p.Next()
		if expectingAnother && !hasNext {
			return p.EofErr()
		}
		if !expectingAnother && p.Line() > startLine {
			break
		}
		if !hasNext {
			p.eof = true
			break // EOF
		}
	}

	return nil
}

func (p *parser) blockContents() error {
	errOpenCurlyBrace := p.openCurlyBrace()
	if errOpenCurlyBrace != nil {
		// single-server configs don't need curly braces
		p.cursor--
	}

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

// directives parses through all the lines for directives
// and it expects the next token to be the first
// directive. It goes until EOF or closing curly brace
// which ends the server block.
func (p *parser) directives() error {
	for p.Next() {
		// end of server block
		if p.Val() == "}" {
			break
		}

		// special case: import directive replaces tokens during parse-time
		if p.Val() == "import" {
			err := p.doImport()
			if err != nil {
				return err
			}
			continue
		}

		// normal case: parse a directive on this line
		if err := p.directive(); err != nil {
			return err
		}
	}
	return nil
}

// doImport swaps out the import directive and its argument
// (a total of 2 tokens) with the tokens in the file specified.
// When the function returns, the cursor is on the token before
// where the import directive was. In other words, call Next()
// to access the first token that was imported.
func (p *parser) doImport() error {
	if !p.NextArg() {
		return p.ArgErr()
	}
	importFile := p.Val()
	if p.NextArg() {
		return p.Err("Import allows only one file to import")
	}

	file, err := os.Open(importFile)
	if err != nil {
		return p.Errf("Could not import %s - %v", importFile, err)
	}
	defer file.Close()
	importedTokens := allTokens(file)

	// Splice out the import directive and its argument (2 tokens total)
	// and insert the imported tokens.
	tokensBefore := p.tokens[:p.cursor-1]
	tokensAfter := p.tokens[p.cursor+1:]
	p.tokens = append(tokensBefore, append(importedTokens, tokensAfter...)...)
	p.cursor -= 2

	return nil
}

// directive collects tokens until the directive's scope
// closes (either end of line or end of curly brace block).
// It expects the currently-loaded token to be a directive
// (or } that ends a server block). The collected tokens
// are loaded into the current server block for later use
// by directive setup functions.
func (p *parser) directive() error {
	dir := p.Val()
	line := p.Line()
	nesting := 0

	if _, ok := ValidDirectives[dir]; !ok {
		return p.Errf("Unknown directive '%s'", dir)
	}

	// The directive itself is appended as a relevant token
	p.block.tokens[dir] = append(p.block.tokens[dir], p.tokens[p.cursor])

	for p.Next() {
		if p.Val() == "{" {
			nesting++
		} else if p.Line()+p.numLineBreaks(p.cursor) > line && nesting == 0 {
			p.cursor-- // read too far
			break
		} else if p.Val() == "}" && nesting > 0 {
			nesting--
		} else if p.Val() == "}" && nesting == 0 {
			return p.Err("Unexpected '}' because no matching opening brace")
		}
		p.block.tokens[dir] = append(p.block.tokens[dir], p.tokens[p.cursor])
	}

	if nesting > 0 {
		return p.EofErr()
	}
	return nil
}

// openCurlyBrace expects the current token to be an
// opening curly brace. This acts like an assertion
// because it returns an error if the token is not
// a opening curly brace. It does not advance the token.
func (p *parser) openCurlyBrace() error {
	if p.Val() != "{" {
		return p.SyntaxErr("{")
	}
	return nil
}

// closeCurlyBrace expects the current token to be
// a closing curly brace. This acts like an assertion
// because it returns an error if the token is not
// a closing curly brace. It does not advance the token.
func (p *parser) closeCurlyBrace() error {
	if p.Val() != "}" {
		return p.SyntaxErr("}")
	}
	return nil
}

// standardAddress turns the accepted host and port patterns
// into a format accepted by net.Dial.
func standardAddress(str string) (host, port string, err error) {
	var schemePort, splitPort string

	if strings.HasPrefix(str, "https://") {
		schemePort = "https"
		str = str[8:]
	} else if strings.HasPrefix(str, "http://") {
		schemePort = "http"
		str = str[7:]
	}

	host, splitPort, err = net.SplitHostPort(str)
	if err != nil {
		host, splitPort, err = net.SplitHostPort(str + ":") // tack on empty port
	}
	if err != nil {
		// ¯\_(ツ)_/¯
		host = str
	}

	if splitPort != "" {
		port = splitPort
	} else {
		port = schemePort
	}

	return
}

type (
	// serverBlock stores tokens by directive name for a
	// single host:port (address)
	serverBlock struct {
		Host, Port string
		Tokens     map[string][]token // directive name to tokens (including directive)
	}

	// multiServerBlock is the same as serverBlock but for
	// multiple addresses that share the same tokens
	multiServerBlock struct {
		addresses []address
		tokens    map[string][]token
	}

	address struct {
		host, port string
	}
)
