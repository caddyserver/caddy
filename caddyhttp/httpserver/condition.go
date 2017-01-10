package httpserver

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/mholt/caddy"
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
	notHasOp     = "not_has"
	startsWithOp = "starts_with"
	endsWithOp   = "ends_with"
	matchOp      = "match"
	notMatchOp   = "not_match"
)

func operatorError(operator string) error {
	return fmt.Errorf("Invalid operator %v", operator)
}

// ifCondition is a 'if' condition.
type ifCondition func(string, string) bool

var ifConditions = map[string]ifCondition{
	isOp:         isFunc,
	notOp:        notFunc,
	hasOp:        hasFunc,
	notHasOp:     notHasFunc,
	startsWithOp: startsWithFunc,
	endsWithOp:   endsWithFunc,
	matchOp:      matchFunc,
	notMatchOp:   notMatchFunc,
}

// isFunc is condition for Is operator.
// It checks for equality.
func isFunc(a, b string) bool {
	return a == b
}

// notFunc is condition for Not operator.
// It checks for inequality.
func notFunc(a, b string) bool {
	return a != b
}

// hasFunc is condition for Has operator.
// It checks if b is a substring of a.
func hasFunc(a, b string) bool {
	return strings.Contains(a, b)
}

// notHasFunc is condition for NotHas operator.
// It checks if b is not a substring of a.
func notHasFunc(a, b string) bool {
	return !strings.Contains(a, b)
}

// startsWithFunc is condition for StartsWith operator.
// It checks if b is a prefix of a.
func startsWithFunc(a, b string) bool {
	return strings.HasPrefix(a, b)
}

// endsWithFunc is condition for EndsWith operator.
// It checks if b is a suffix of a.
func endsWithFunc(a, b string) bool {
	return strings.HasSuffix(a, b)
}

// matchFunc is condition for Match operator.
// It does regexp matching of a against pattern in b
// and returns if they match.
func matchFunc(a, b string) bool {
	matched, _ := regexp.MatchString(b, a)
	return matched
}

// notMatchFunc is condition for NotMatch operator.
// It does regexp matching of a against pattern in b
// and returns if they do not match.
func notMatchFunc(a, b string) bool {
	matched, _ := regexp.MatchString(b, a)
	return !matched
}

// ifCond is statement for a IfMatcher condition.
type ifCond struct {
	a  string
	op string
	b  string
}

// newIfCond creates a new If condition.
func newIfCond(a, operator, b string) (ifCond, error) {
	if _, ok := ifConditions[operator]; !ok {
		return ifCond{}, operatorError(operator)
	}
	return ifCond{
		a:  a,
		op: operator,
		b:  b,
	}, nil
}

// True returns true if the condition is true and false otherwise.
// If r is not nil, it replaces placeholders before comparison.
func (i ifCond) True(r *http.Request) bool {
	if c, ok := ifConditions[i.op]; ok {
		a, b := i.a, i.b
		if r != nil {
			replacer := NewReplacer(r, nil, "")
			a = replacer.Replace(i.a)
			b = replacer.Replace(i.b)
		}
		return c(a, b)
	}
	return false
}

// IfMatcher is a RequestMatcher for 'if' conditions.
type IfMatcher struct {
	ifs  []ifCond // list of If
	isOr bool     // if true, conditions are 'or' instead of 'and'
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
// If true, remaining arguments in the dispinser are cleard to keep the dispenser valid for use.
func IfMatcherKeyword(c *caddy.Controller) bool {
	if c.Val() == "if" || c.Val() == "if_op" {
		// clear remaining args
		c.RemainingArgs()
		return true
	}
	return false
}
