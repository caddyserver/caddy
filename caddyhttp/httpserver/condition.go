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
	"net/http"
	"regexp"
	"strings"

	"github.com/caddyserver/caddy"
)

// SetupIfMatcher parses `if` or `if_op` in the current dispenser block.
// It returns a RequestMatcher and an error if any.
func SetupIfMatcher(controller *caddy.Controller) (RequestMatcher, error) {
	var c = controller.Dispenser // copy the dispenser
	var matcher IfMatcher
	for c.NextBlock() {
		switch c.Val() {
		case "if":
			args1 := c.RemainingArgs()
			if len(args1) != 3 {
				return matcher, c.ArgErr()
			}
			ifc, err := newIfCond(args1[0], args1[1], args1[2])
			if err != nil {
				return matcher, err
			}
			matcher.ifs = append(matcher.ifs, ifc)
			matcher.Enabled = true
		case "if_op":
			if !c.NextArg() {
				return matcher, c.ArgErr()
			}
			switch c.Val() {
			case "and":
				matcher.isOr = false
			case "or":
				matcher.isOr = true
			default:
				return matcher, c.ArgErr()
			}
		}
	}
	return matcher, nil
}

// operators
const (
	isOp         = "is"
	notOp        = "not"
	hasOp        = "has"
	startsWithOp = "starts_with"
	endsWithOp   = "ends_with"
	matchOp      = "match"
)

// ifCondition is a 'if' condition.
type ifFunc func(a, b string) bool

// ifCond is statement for a IfMatcher condition.
type ifCond struct {
	a   string
	op  string
	b   string
	neg bool
	rex *regexp.Regexp
	f   ifFunc
}

// newIfCond creates a new If condition.
func newIfCond(a, op, b string) (ifCond, error) {
	i := ifCond{a: a, op: op, b: b}
	if strings.HasPrefix(op, "not_") {
		i.neg = true
		i.op = op[4:]
	}

	switch i.op {
	case isOp:
		// It checks for equality.
		i.f = i.isFunc
	case notOp:
		// It checks for inequality.
		i.f = i.notFunc
	case hasOp:
		// It checks if b is a substring of a.
		i.f = strings.Contains
	case startsWithOp:
		// It checks if b is a prefix of a.
		i.f = strings.HasPrefix
	case endsWithOp:
		// It checks if b is a suffix of a.
		i.f = strings.HasSuffix
	case matchOp:
		// It does regexp matching of a against pattern in b and returns if they match.
		var err error
		if i.rex, err = regexp.Compile(i.b); err != nil {
			return ifCond{}, fmt.Errorf("Invalid regular expression: '%s', %v", i.b, err)
		}
		i.f = i.matchFunc
	default:
		return ifCond{}, fmt.Errorf("Invalid operator %v", i.op)
	}

	return i, nil
}

// isFunc is condition for Is operator.
func (i ifCond) isFunc(a, b string) bool {
	return a == b
}

// notFunc is condition for Not operator.
func (i ifCond) notFunc(a, b string) bool {
	return a != b
}

// matchFunc is condition for Match operator.
func (i ifCond) matchFunc(a, b string) bool {
	return i.rex.MatchString(a)
}

// True returns true if the condition is true and false otherwise.
// If r is not nil, it replaces placeholders before comparison.
func (i ifCond) True(r *http.Request) bool {
	if i.f != nil {
		a, b := i.a, i.b
		if r != nil {
			replacer := NewReplacer(r, nil, "")
			a = replacer.Replace(i.a)
			if i.op != matchOp {
				b = replacer.Replace(i.b)
			}
		}
		if i.neg {
			return !i.f(a, b)
		}
		return i.f(a, b)
	}
	return i.neg // false if not negated, true otherwise
}

// IfMatcher is a RequestMatcher for 'if' conditions.
type IfMatcher struct {
	Enabled bool     // if true, matcher has been configured; otherwise it's no-op
	ifs     []ifCond // list of If
	isOr    bool     // if true, conditions are 'or' instead of 'and'
}

// Match satisfies RequestMatcher interface.
// It returns true if the conditions in m are true.
func (m IfMatcher) Match(r *http.Request) bool {
	if m.isOr {
		return m.Or(r)
	}
	return m.And(r)
}

// And returns true if all conditions in m are true.
func (m IfMatcher) And(r *http.Request) bool {
	for _, i := range m.ifs {
		if !i.True(r) {
			return false
		}
	}
	return true
}

// Or returns true if any of the conditions in m is true.
func (m IfMatcher) Or(r *http.Request) bool {
	for _, i := range m.ifs {
		if i.True(r) {
			return true
		}
	}
	return false
}

// IfMatcherKeyword checks if the next value in the dispenser is a keyword for 'if' config block.
// If true, remaining arguments in the dispenser are cleared to keep the dispenser valid for use.
func IfMatcherKeyword(c *caddy.Controller) bool {
	if c.Val() == "if" || c.Val() == "if_op" {
		// clear remaining args
		c.RemainingArgs()
		return true
	}
	return false
}
