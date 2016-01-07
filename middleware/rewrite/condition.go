package rewrite

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/mholt/caddy/middleware"
)

// Operators
const (
	Is         = "is"
	Not        = "not"
	Has        = "has"
	NotHas     = "not_has"
	StartsWith = "starts_with"
	EndsWith   = "ends_with"
	Match      = "match"
	NotMatch   = "not_match"
)

func operatorError(operator string) error {
	return fmt.Errorf("Invalid operator %v", operator)
}

func newReplacer(r *http.Request) middleware.Replacer {
	return middleware.NewReplacer(r, nil, "")
}

// condition is a rewrite condition.
type condition func(string, string) bool

var conditions = map[string]condition{
	Is:         isFunc,
	Not:        notFunc,
	Has:        hasFunc,
	NotHas:     notHasFunc,
	StartsWith: startsWithFunc,
	EndsWith:   endsWithFunc,
	Match:      matchFunc,
	NotMatch:   notMatchFunc,
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

// If is statement for a rewrite condition.
type If struct {
	A        string
	Operator string
	B        string
}

// True returns true if the condition is true and false otherwise.
// If r is not nil, it replaces placeholders before comparison.
func (i If) True(r *http.Request) bool {
	if c, ok := conditions[i.Operator]; ok {
		a, b := i.A, i.B
		if r != nil {
			replacer := newReplacer(r)
			a = replacer.Replace(i.A)
			b = replacer.Replace(i.B)
		}
		return c(a, b)
	}
	return false
}

// NewIf creates a new If condition.
func NewIf(a, operator, b string) (If, error) {
	if _, ok := conditions[operator]; !ok {
		return If{}, operatorError(operator)
	}
	return If{
		A:        a,
		Operator: operator,
		B:        b,
	}, nil
}
