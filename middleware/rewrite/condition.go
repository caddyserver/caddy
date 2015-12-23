package rewrite

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/mholt/caddy/middleware"
)

const (
	// Operators
	Is         = "is"
	Not        = "not"
	Has        = "has"
	StartsWith = "starts_with"
	EndsWith   = "ends_with"
	Match      = "match"
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
	StartsWith: startsWithFunc,
	EndsWith:   endsWithFunc,
	Match:      matchFunc,
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
func matchFunc(a, b string) bool {
	matched, _ := regexp.MatchString(b, a)
	return matched
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
