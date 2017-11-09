// Copyright 2015 Light Code Labs, LLC
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

package httpserver

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"regexp"
	"strings"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyfile"
)

// GetRequestMatcher returns the RequestMatcher, if any, for
// the current token. Used by directive middlewares when parsing
// their tokens.
func GetRequestMatcher(c *caddy.Controller) RequestMatcher {
	if reqm, ok := c.Data().(RequestMatcher); ok {
		return reqm
	}
	return nil
}

// parseIfTokens parses an 'if' statement and its block, and attaches a
// request matcher to the relevant directive tokens. It returns a map
// of tokens from inside the block which should be re-assimilated back
// into the main ServerBlock.
func parseIfTokens(tkns []caddyfile.Token) (map[string][]caddyfile.Token, error) {
	// first, parse just the header and make the matcher
	var conditions []MatchOp
	var conjunctions []string
	i := 1 // counter is used outside of loop
	for ; i < len(tkns); i++ {
		if tkns[i].Text == "{" {
			// end of header, beginning of block
			break
		}

		if tkns[i].Text == "and" || tkns[i].Text == "or" {
			conjunctions = append(conjunctions, tkns[i].Text)
			continue
		}

		// if not a conjunction, then this must be a condition, which requires precisely 3 tokens
		if len(tkns) <= i+2 {
			return nil, fmt.Errorf("malformed if statement; format must be: A op B [and|or]...")
		}

		opText := tkns[i+1].Text
		var negated bool
		if strings.HasPrefix(opText, "not_") {
			opText = strings.TrimPrefix(opText, "not_")
			negated = true
		}
		opf, ok := matchOps[opText]
		if !ok {
			return nil, fmt.Errorf("unknown operator '%s'", opText)
		}
		conditions = append(conditions, MatchOp{
			Left:   tkns[i].Text,
			Right:  tkns[i+2].Text,
			Op:     opf,
			Negate: negated,
		})
		i += 2
	}

	if len(conditions) == 0 {
		return nil, fmt.Errorf("no conditions given")
	}
	if len(conjunctions) != len(conditions)-1 {
		return nil, fmt.Errorf("for %d conditions, expected exactly %d conjunctions but got %d",
			len(conditions), len(conditions)-1, len(conjunctions))
	}
	matcher, err := makeRequestMatcher(conditions, conjunctions)
	if err != nil {
		return nil, err
	}

	// parse the rest of the block and attach the matcher to each nested directive
	innerTokens, err := caddyfile.ParseBlockTokens(tkns[i+1:len(tkns)-1], directives)
	if err != nil {
		return nil, err
	}

	var nesting int
	for _, tokens := range innerTokens {
		for i := range tokens {
			if tokens[i].Text == "{" {
				nesting++
				continue
			}
			if tokens[i].Text == "}" {
				nesting--
				continue
			}

			// if this is a directive token, attach the matcher to it
			// (TODO: it would be nice to abstract away this logic...)
			if nesting == 0 &&
				(i == 0 ||
					(tokens[i-1].File != tokens[i].File ||
						(tokens[i-1].Line+strings.Count(tokens[i-1].Text, "\n")) < tokens[i].Line)) {
				tokens[i].Data = matcher
			}
		}
	}

	return innerTokens, nil
}

// MatchOpFunc is a function that implements a matcher condition operator.
type MatchOpFunc func(left, right string) (bool, error)

// MatchOp holds an operation for request matching.
type MatchOp struct {
	Left, Right string      // left and right values
	Op          MatchOpFunc // the operator function
	Negate      bool        // whether to negate the result
}

// matchOps is a list of matching operations that are understood. The
// inverse of each one is implicitly added (no need to prepend "not_").
var matchOps = map[string]MatchOpFunc{
	"is": func(left, right string) (bool, error) {
		return left == right, nil
	},
	"has": func(left, right string) (bool, error) {
		return strings.Contains(left, right), nil
	},
	"starts_with": func(left, right string) (bool, error) {
		return strings.HasPrefix(left, right), nil
	},
	"ends_with": func(left, right string) (bool, error) {
		return strings.HasSuffix(left, right), nil
	},
	"matches": func(left, right string) (bool, error) {
		regex, err := regexp.Compile(right)
		if err != nil {
			return false, fmt.Errorf("invalid regular expression `%s`: %v", right, err)
		}
		return regex.MatchString(left), nil
	},
	"in_range": func(left, right string) (bool, error) {
		addr := net.ParseIP(left)
		if addr == nil {
			return false, fmt.Errorf("unable to parse IP address: %s", left)
		}
		_, ipnet, err := net.ParseCIDR(right)
		if err != nil {
			return false, fmt.Errorf("parsing CIDR range: %v", err)
		}
		return ipnet.Contains(addr), nil
	},
}

// makeRequestMatcher makes a request matcher given the list of conditions
// and their associated conjunctions (order matters).
func makeRequestMatcher(conditions []MatchOp, conjunctions []string) (ifRequestMatcher, error) {
	// these error cases shouldn't happen because they should be
	// checked in an earlier function, but just in case...
	if len(conditions) == 0 {
		return nil, fmt.Errorf("no conditions")
	}
	if len(conjunctions) != len(conditions)-1 {
		return nil, fmt.Errorf("not the right number of conjunctions")
	}

	return func(req *http.Request) bool {
		repl, ok := req.Context().Value(ReplacerCtxKey).(*replacer)
		if !ok || repl == nil {
			log.Println("[ERROR] Unable to evaluate if statement because request context has no replacer")
			return false
		}

		var aggregate bool
		for i, cond := range conditions {
			if i > 0 && conjunctions[i-1] == "and" && aggregate == false {
				// lazy evaluation; since we don't (yet?) support
				// grouping conditions and evaluation is purely linear,
				// we have hit our stopping criteria if currently
				// false and the next condition MUST ALSO be true
				// (false && B must necessarily be false regardless of B)
				return false
			}

			left := repl.Replace(cond.Left)
			right := repl.Replace(cond.Right)
			match, err := cond.Op(left, right)
			if err != nil {
				log.Printf("[ERROR] Evaluating 'if' statement: %v", err)
				continue
			}
			if cond.Negate {
				match = !match
			}

			if i == 0 {
				aggregate = match
				continue
			}
			if conjunctions[i-1] == "and" {
				aggregate = aggregate && match
			} else if conjunctions[i-1] == "or" {
				aggregate = aggregate || match
			}
		}

		return aggregate
	}, nil
}

// ifRequestMatcher is an implementation of RequestMatcher.
type ifRequestMatcher func(*http.Request) bool

func (m ifRequestMatcher) Match(req *http.Request) bool {
	return m(req)
}
