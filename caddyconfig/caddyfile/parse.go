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
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
)

// Parse parses the input just enough to group tokens, in
// order, by server block. No further parsing is performed.
// Server blocks are returned in the order in which they appear.
// Directives that do not appear in validDirectives will cause
// an error. If you do not want to check for valid directives,
// pass in nil instead.
//
// Environment variables in {$ENVIRONMENT_VARIABLE} notation
// will be replaced before parsing begins.
func Parse(filename string, input []byte) ([]ServerBlock, error) {
	// unfortunately, we must copy the input because parsing must
	// remain a read-only operation, but we have to expand environment
	// variables before we parse, which changes the underlying array (#4422)
	inputCopy := make([]byte, len(input))
	copy(inputCopy, input)

	tokens, err := allTokens(filename, inputCopy)
	if err != nil {
		return nil, err
	}
	p := parser{
		Dispenser: NewDispenser(tokens),
		importGraph: importGraph{
			nodes: make(map[string]struct{}),
			edges: make(adjacency),
		},
	}
	return p.parseAll()
}

// allTokens lexes the entire input, but does not parse it.
// It returns all the tokens from the input, unstructured
// and in order. It may mutate input as it expands env vars.
func allTokens(filename string, input []byte) ([]Token, error) {
	return Tokenize(replaceEnvVars(input), filename)
}

// replaceEnvVars replaces all occurrences of environment variables.
// It mutates the underlying array and returns the updated slice.
func replaceEnvVars(input []byte) []byte {
	var offset int
	for {
		begin := bytes.Index(input[offset:], spanOpen)
		if begin < 0 {
			break
		}
		begin += offset // make beginning relative to input, not offset
		end := bytes.Index(input[begin+len(spanOpen):], spanClose)
		if end < 0 {
			break
		}
		end += begin + len(spanOpen) // make end relative to input, not begin

		// get the name; if there is no name, skip it
		envString := input[begin+len(spanOpen) : end]
		if len(envString) == 0 {
			offset = end + len(spanClose)
			continue
		}

		// split the string into a key and an optional default
		envParts := strings.SplitN(string(envString), envVarDefaultDelimiter, 2)

		// do a lookup for the env var, replace with the default if not found
		envVarValue, found := os.LookupEnv(envParts[0])
		if !found && len(envParts) == 2 {
			envVarValue = envParts[1]
		}

		// get the value of the environment variable
		// note that this causes one-level deep chaining
		envVarBytes := []byte(envVarValue)

		// splice in the value
		input = append(input[:begin],
			append(envVarBytes, input[end+len(spanClose):]...)...)

		// continue at the end of the replacement
		offset = begin + len(envVarBytes)
	}
	return input
}

type parser struct {
	*Dispenser
	block           ServerBlock // current server block being parsed
	eof             bool        // if we encounter a valid EOF in a hard place
	definedSnippets map[string][]Token
	nesting         int
	importGraph     importGraph
}

func (p *parser) parseAll() ([]ServerBlock, error) {
	var blocks []ServerBlock

	for p.Next() {
		err := p.parseOne()
		if err != nil {
			return blocks, err
		}
		if len(p.block.Keys) > 0 || len(p.block.Segments) > 0 {
			blocks = append(blocks, p.block)
		}
		if p.nesting > 0 {
			return blocks, p.EOFErr()
		}
	}

	return blocks, nil
}

func (p *parser) parseOne() error {
	p.block = ServerBlock{}
	return p.begin()
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

	if ok, name := p.isNamedRoute(); ok {
		// we just need a dummy leading token to ease parsing later
		nameToken := p.Token()
		nameToken.Text = name

		// named routes only have one key, the route name
		p.block.Keys = []Token{nameToken}
		p.block.IsNamedRoute = true

		// get all the tokens from the block, including the braces
		tokens, err := p.blockTokens(true)
		if err != nil {
			return err
		}
		tokens = append([]Token{nameToken}, tokens...)
		p.block.Segments = []Segment{tokens}
		return nil
	}

	if ok, name := p.isSnippet(); ok {
		if p.definedSnippets == nil {
			p.definedSnippets = map[string][]Token{}
		}
		if _, found := p.definedSnippets[name]; found {
			return p.Errf("redeclaration of previously declared snippet %s", name)
		}
		// consume all tokens til matched close brace
		tokens, err := p.blockTokens(false)
		if err != nil {
			return err
		}
		// Just as we need to track which file the token comes from, we need to
		// keep track of which snippet the token comes from. This is helpful
		// in tracking import cycles across files/snippets by namespacing them.
		// Without this, we end up with false-positives in cycle-detection.
		for k, v := range tokens {
			v.snippetName = name
			tokens[k] = v
		}
		p.definedSnippets[name] = tokens
		// empty block keys so we don't save this block as a real server.
		p.block.Keys = nil
		return nil
	}

	return p.blockContents()
}

func (p *parser) addresses() error {
	var expectingAnother bool

	for {
		value := p.Val()
		token := p.Token()

		// Reject request matchers if trying to define them globally
		if strings.HasPrefix(value, "@") {
			return p.Errf("request matchers may not be defined globally, they must be in a site block; found %s", value)
		}

		// Special case: import directive replaces tokens during parse-time
		if value == "import" && p.isNewLine() {
			err := p.doImport(0)
			if err != nil {
				return err
			}
			continue
		}

		// Open brace definitely indicates end of addresses
		if value == "{" {
			if expectingAnother {
				return p.Errf("Expected another address but had '%s' - check for extra comma", value)
			}
			// Mark this server block as being defined with braces.
			// This is used to provide a better error message when
			// the user may have tried to define two server blocks
			// without having used braces, which are required in
			// that case.
			p.block.HasBraces = true
			break
		}

		// Users commonly forget to place a space between the address and the '{'
		if strings.HasSuffix(value, "{") {
			return p.Errf("Site addresses cannot end with a curly brace: '%s' - put a space between the token and the brace", value)
		}

		if value != "" { // empty token possible if user typed ""
			// Trailing comma indicates another address will follow, which
			// may possibly be on the next line
			if value[len(value)-1] == ',' {
				value = value[:len(value)-1]
				expectingAnother = true
			} else {
				expectingAnother = false // but we may still see another one on this line
			}

			// If there's a comma here, it's probably because they didn't use a space
			// between their two domains, e.g. "foo.com,bar.com", which would not be
			// parsed as two separate site addresses.
			if strings.Contains(value, ",") {
				return p.Errf("Site addresses cannot contain a comma ',': '%s' - put a space after the comma to separate site addresses", value)
			}

			// After the above, a comma surrounded by spaces would result
			// in an empty token which we should ignore
			if value != "" {
				// Add the token as a site address
				token.Text = value
				p.block.Keys = append(p.block.Keys, token)
			}
		}

		// Advance token and possibly break out of loop or return error
		hasNext := p.Next()
		if expectingAnother && !hasNext {
			return p.EOFErr()
		}
		if !hasNext {
			p.eof = true
			break // EOF
		}
		if !expectingAnother && p.isNewLine() {
			break
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

	// only look for close curly brace if there was an opening
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
			// p.nesting has already been decremented
			break
		}

		// special case: import directive replaces tokens during parse-time
		if p.Val() == "import" {
			err := p.doImport(1)
			if err != nil {
				return err
			}
			p.cursor-- // cursor is advanced when we continue, so roll back one more
			continue
		}

		// normal case: parse a directive as a new segment
		// (a "segment" is a line which starts with a directive
		// and which ends at the end of the line or at the end of
		// the block that is opened at the end of the line)
		if err := p.directive(); err != nil {
			return err
		}
	}

	return nil
}

// doImport swaps out the import directive and its argument
// (a total of 2 tokens) with the tokens in the specified file
// or globbing pattern. When the function returns, the cursor
// is on the token before where the import directive was. In
// other words, call Next() to access the first token that was
// imported.
func (p *parser) doImport(nesting int) error {
	// syntax checks
	if !p.NextArg() {
		return p.ArgErr()
	}
	importPattern := p.Val()
	if importPattern == "" {
		return p.Err("Import requires a non-empty filepath")
	}

	// grab remaining args as placeholder replacements
	args := p.RemainingArgs()

	// set up a replacer for non-variadic args replacement
	repl := makeArgsReplacer(args)

	// grab all the tokens (if it exists) from within a block that follows the import
	var blockTokens []Token
	for currentNesting := p.Nesting(); p.NextBlock(currentNesting); {
		blockTokens = append(blockTokens, p.Token())
	}
	// initialize with size 1
	blockMapping := make(map[string][]Token, 1)
	if len(blockTokens) > 0 {
		// use such tokens to create a new dispenser, and then use it to parse each block
		bd := NewDispenser(blockTokens)
		for bd.Next() {
			// see if we can grab a key
			var currentMappingKey string
			if bd.Val() == "{" {
				return p.Err("anonymous blocks are not supported")
			}
			currentMappingKey = bd.Val()
			currentMappingTokens := []Token{}
			// read all args until end of line / {
			if bd.NextArg() {
				currentMappingTokens = append(currentMappingTokens, bd.Token())
				for bd.NextArg() {
					currentMappingTokens = append(currentMappingTokens, bd.Token())
				}
				// TODO(elee1766): we don't enter another mapping here because it's annoying to extract the { and } properly.
				// maybe someone can do that in the future
			} else {
				// attempt to enter a block and add tokens to the currentMappingTokens
				for mappingNesting := bd.Nesting(); bd.NextBlock(mappingNesting); {
					currentMappingTokens = append(currentMappingTokens, bd.Token())
				}
			}
			blockMapping[currentMappingKey] = currentMappingTokens
		}
	}

	// splice out the import directive and its arguments
	// (2 tokens, plus the length of args)
	tokensBefore := p.tokens[:p.cursor-1-len(args)-len(blockTokens)]
	tokensAfter := p.tokens[p.cursor+1:]
	var importedTokens []Token
	var nodes []string

	// first check snippets. That is a simple, non-recursive replacement
	if p.definedSnippets != nil && p.definedSnippets[importPattern] != nil {
		importedTokens = p.definedSnippets[importPattern]
		if len(importedTokens) > 0 {
			// just grab the first one
			nodes = append(nodes, fmt.Sprintf("%s:%s", importedTokens[0].File, importedTokens[0].snippetName))
		}
	} else {
		// make path relative to the file of the _token_ being processed rather
		// than current working directory (issue #867) and then use glob to get
		// list of matching filenames
		absFile, err := caddy.FastAbs(p.Dispenser.File())
		if err != nil {
			return p.Errf("Failed to get absolute path of file: %s: %v", p.Dispenser.File(), err)
		}

		var matches []string
		var globPattern string
		if !filepath.IsAbs(importPattern) {
			globPattern = filepath.Join(filepath.Dir(absFile), importPattern)
		} else {
			globPattern = importPattern
		}
		if strings.Count(globPattern, "*") > 1 || strings.Count(globPattern, "?") > 1 ||
			(strings.Contains(globPattern, "[") && strings.Contains(globPattern, "]")) {
			// See issue #2096 - a pattern with many glob expansions can hang for too long
			return p.Errf("Glob pattern may only contain one wildcard (*), but has others: %s", globPattern)
		}
		matches, err = filepath.Glob(globPattern)
		if err != nil {
			return p.Errf("Failed to use import pattern %s: %v", importPattern, err)
		}
		if len(matches) == 0 {
			if strings.ContainsAny(globPattern, "*?[]") {
				caddy.Log().Warn("No files matching import glob pattern", zap.String("pattern", importPattern))
			} else {
				return p.Errf("File to import not found: %s", importPattern)
			}
		} else {
			// See issue #5295 - should skip any files that start with a . when iterating over them.
			sep := string(filepath.Separator)
			segGlobPattern := strings.Split(globPattern, sep)
			if strings.HasPrefix(segGlobPattern[len(segGlobPattern)-1], "*") {
				var tmpMatches []string
				for _, m := range matches {
					seg := strings.Split(m, sep)
					if !strings.HasPrefix(seg[len(seg)-1], ".") {
						tmpMatches = append(tmpMatches, m)
					}
				}
				matches = tmpMatches
			}
		}

		// collect all the imported tokens
		for _, importFile := range matches {
			newTokens, err := p.doSingleImport(importFile)
			if err != nil {
				return err
			}
			importedTokens = append(importedTokens, newTokens...)
		}
		nodes = matches
	}

	nodeName := p.File()
	if p.Token().snippetName != "" {
		nodeName += fmt.Sprintf(":%s", p.Token().snippetName)
	}
	p.importGraph.addNode(nodeName)
	p.importGraph.addNodes(nodes)
	if err := p.importGraph.addEdges(nodeName, nodes); err != nil {
		p.importGraph.removeNodes(nodes)
		return err
	}

	// copy the tokens so we don't overwrite p.definedSnippets
	tokensCopy := make([]Token, 0, len(importedTokens))

	var (
		maybeSnippet   bool
		maybeSnippetId bool
		index          int
	)

	// run the argument replacer on the tokens
	// golang for range slice return a copy of value
	// similarly, append also copy value
	for i, token := range importedTokens {
		// update the token's imports to refer to import directive filename, line number and snippet name if there is one
		if token.snippetName != "" {
			token.imports = append(token.imports, fmt.Sprintf("%s:%d (import %s)", p.File(), p.Line(), token.snippetName))
		} else {
			token.imports = append(token.imports, fmt.Sprintf("%s:%d (import)", p.File(), p.Line()))
		}

		// naive way of determine snippets, as snippets definition can only follow name + block
		// format, won't check for nesting correctness or any other error, that's what parser does.
		if !maybeSnippet && nesting == 0 {
			// first of the line
			if i == 0 || isNextOnNewLine(tokensCopy[i-1], token) {
				index = 0
			} else {
				index++
			}

			if index == 0 && len(token.Text) >= 3 && strings.HasPrefix(token.Text, "(") && strings.HasSuffix(token.Text, ")") {
				maybeSnippetId = true
			}
		}

		switch token.Text {
		case "{":
			nesting++
			if index == 1 && maybeSnippetId && nesting == 1 {
				maybeSnippet = true
				maybeSnippetId = false
			}
		case "}":
			nesting--
			if nesting == 0 && maybeSnippet {
				maybeSnippet = false
			}
		}
		// if it is {block}, we substitute with all tokens in the block
		// if it is {blocks.*}, we substitute with the tokens in the mapping for the *
		var skip bool
		var tokensToAdd []Token
		switch {
		case token.Text == "{block}":
			tokensToAdd = blockTokens
		case strings.HasPrefix(token.Text, "{blocks.") && strings.HasSuffix(token.Text, "}"):
			// {blocks.foo.bar} will be extracted to key `foo.bar`
			blockKey := strings.TrimPrefix(strings.TrimSuffix(token.Text, "}"), "{blocks.")
			val, ok := blockMapping[blockKey]
			if ok {
				tokensToAdd = val
			}
		default:
			skip = true
		}
		if !skip {
			if len(tokensToAdd) == 0 {
				// if there is no content in the snippet block, don't do any replacement
				// this allows snippets which contained {block}/{block.*} before this change to continue functioning as normal
				tokensCopy = append(tokensCopy, token)
			} else {
				tokensCopy = append(tokensCopy, tokensToAdd...)
			}
			continue
		}

		if maybeSnippet {
			tokensCopy = append(tokensCopy, token)
			continue
		}

		foundVariadic, startIndex, endIndex := parseVariadic(token, len(args))
		if foundVariadic {
			for _, arg := range args[startIndex:endIndex] {
				token.Text = arg
				tokensCopy = append(tokensCopy, token)
			}
		} else {
			token.Text = repl.ReplaceKnown(token.Text, "")
			tokensCopy = append(tokensCopy, token)
		}
	}

	// splice the imported tokens in the place of the import statement
	// and rewind cursor so Next() will land on first imported token
	p.tokens = append(tokensBefore, append(tokensCopy, tokensAfter...)...)
	p.cursor -= len(args) + len(blockTokens) + 1

	return nil
}

// doSingleImport lexes the individual file at importFile and returns
// its tokens or an error, if any.
func (p *parser) doSingleImport(importFile string) ([]Token, error) {
	file, err := os.Open(importFile)
	if err != nil {
		return nil, p.Errf("Could not import %s: %v", importFile, err)
	}
	defer file.Close()

	if info, err := file.Stat(); err != nil {
		return nil, p.Errf("Could not import %s: %v", importFile, err)
	} else if info.IsDir() {
		return nil, p.Errf("Could not import %s: is a directory", importFile)
	}

	input, err := io.ReadAll(file)
	if err != nil {
		return nil, p.Errf("Could not read imported file %s: %v", importFile, err)
	}

	// only warning in case of empty files
	if len(input) == 0 || len(strings.TrimSpace(string(input))) == 0 {
		caddy.Log().Warn("Import file is empty", zap.String("file", importFile))
		return []Token{}, nil
	}

	importedTokens, err := allTokens(importFile, input)
	if err != nil {
		return nil, p.Errf("Could not read tokens while importing %s: %v", importFile, err)
	}

	// Tack the file path onto these tokens so errors show the imported file's name
	// (we use full, absolute path to avoid bugs: issue #1892)
	filename, err := caddy.FastAbs(importFile)
	if err != nil {
		return nil, p.Errf("Failed to get absolute path of file: %s: %v", importFile, err)
	}
	for i := 0; i < len(importedTokens); i++ {
		importedTokens[i].File = filename
	}

	return importedTokens, nil
}

// directive collects tokens until the directive's scope
// closes (either end of line or end of curly brace block).
// It expects the currently-loaded token to be a directive
// (or } that ends a server block). The collected tokens
// are loaded into the current server block for later use
// by directive setup functions.
func (p *parser) directive() error {
	// a segment is a list of tokens associated with this directive
	var segment Segment

	// the directive itself is appended as a relevant token
	segment = append(segment, p.Token())

	for p.Next() {
		if p.Val() == "{" {
			p.nesting++
			if !p.isNextOnNewLine() && p.Token().wasQuoted == 0 {
				return p.Err("Unexpected next token after '{' on same line")
			}
			if p.isNewLine() {
				return p.Err("Unexpected '{' on a new line; did you mean to place the '{' on the previous line?")
			}
		} else if p.Val() == "{}" {
			if p.isNextOnNewLine() && p.Token().wasQuoted == 0 {
				return p.Err("Unexpected '{}' at end of line")
			}
		} else if p.isNewLine() && p.nesting == 0 {
			p.cursor-- // read too far
			break
		} else if p.Val() == "}" && p.nesting > 0 {
			p.nesting--
		} else if p.Val() == "}" && p.nesting == 0 {
			return p.Err("Unexpected '}' because no matching opening brace")
		} else if p.Val() == "import" && p.isNewLine() {
			if err := p.doImport(1); err != nil {
				return err
			}
			p.cursor-- // cursor is advanced when we continue, so roll back one more
			continue
		}

		segment = append(segment, p.Token())
	}

	p.block.Segments = append(p.block.Segments, segment)

	if p.nesting > 0 {
		return p.EOFErr()
	}

	return nil
}

// openCurlyBrace expects the current token to be an
// opening curly brace. This acts like an assertion
// because it returns an error if the token is not
// a opening curly brace. It does NOT advance the token.
func (p *parser) openCurlyBrace() error {
	if p.Val() != "{" {
		return p.SyntaxErr("{")
	}
	return nil
}

// closeCurlyBrace expects the current token to be
// a closing curly brace. This acts like an assertion
// because it returns an error if the token is not
// a closing curly brace. It does NOT advance the token.
func (p *parser) closeCurlyBrace() error {
	if p.Val() != "}" {
		return p.SyntaxErr("}")
	}
	return nil
}

func (p *parser) isNamedRoute() (bool, string) {
	keys := p.block.Keys
	// A named route block is a single key with parens, prefixed with &.
	if len(keys) == 1 && strings.HasPrefix(keys[0].Text, "&(") && strings.HasSuffix(keys[0].Text, ")") {
		return true, strings.TrimSuffix(keys[0].Text[2:], ")")
	}
	return false, ""
}

func (p *parser) isSnippet() (bool, string) {
	keys := p.block.Keys
	// A snippet block is a single key with parens. Nothing else qualifies.
	if len(keys) == 1 && strings.HasPrefix(keys[0].Text, "(") && strings.HasSuffix(keys[0].Text, ")") {
		return true, strings.TrimSuffix(keys[0].Text[1:], ")")
	}
	return false, ""
}

// read and store everything in a block for later replay.
func (p *parser) blockTokens(retainCurlies bool) ([]Token, error) {
	// block must have curlies.
	err := p.openCurlyBrace()
	if err != nil {
		return nil, err
	}
	nesting := 1 // count our own nesting
	tokens := []Token{}
	if retainCurlies {
		tokens = append(tokens, p.Token())
	}
	for p.Next() {
		if p.Val() == "}" {
			nesting--
			if nesting == 0 {
				if retainCurlies {
					tokens = append(tokens, p.Token())
				}
				break
			}
		}
		if p.Val() == "{" {
			nesting++
		}
		tokens = append(tokens, p.tokens[p.cursor])
	}
	// make sure we're matched up
	if nesting != 0 {
		return nil, p.SyntaxErr("}")
	}
	return tokens, nil
}

// ServerBlock associates any number of keys from the
// head of the server block with tokens, which are
// grouped by segments.
type ServerBlock struct {
	HasBraces    bool
	Keys         []Token
	Segments     []Segment
	IsNamedRoute bool
}

func (sb ServerBlock) GetKeysText() []string {
	res := []string{}
	for _, k := range sb.Keys {
		res = append(res, k.Text)
	}
	return res
}

// DispenseDirective returns a dispenser that contains
// all the tokens in the server block.
func (sb ServerBlock) DispenseDirective(dir string) *Dispenser {
	var tokens []Token
	for _, seg := range sb.Segments {
		if len(seg) > 0 && seg[0].Text == dir {
			tokens = append(tokens, seg...)
		}
	}
	return NewDispenser(tokens)
}

// Segment is a list of tokens which begins with a directive
// and ends at the end of the directive (either at the end of
// the line, or at the end of a block it opens).
type Segment []Token

// Directive returns the directive name for the segment.
// The directive name is the text of the first token.
func (s Segment) Directive() string {
	if len(s) > 0 {
		return s[0].Text
	}
	return ""
}

// spanOpen and spanClose are used to bound spans that
// contain the name of an environment variable.
var (
	spanOpen, spanClose    = []byte{'{', '$'}, []byte{'}'}
	envVarDefaultDelimiter = ":"
)
