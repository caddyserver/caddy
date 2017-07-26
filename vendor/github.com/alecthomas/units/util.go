package units

import (
	"errors"
	"fmt"
	"strings"
)

var (
	siUnits = []string{"", "K", "M", "G", "T", "P", "E"}
)

func ToString(n int64, scale int64, suffix, baseSuffix string) string {
	mn := len(siUnits)
	out := make([]string, mn)
	for i, m := range siUnits {
		if n%scale != 0 || i == 0 && n == 0 {
			s := suffix
			if i == 0 {
				s = baseSuffix
			}
			out[mn-1-i] = fmt.Sprintf("%d%s%s", n%scale, m, s)
		}
		n /= scale
		if n == 0 {
			break
		}
	}
	return strings.Join(out, "")
}

// Below code ripped straight from http://golang.org/src/pkg/time/format.go?s=33392:33438#L1123
var errLeadingInt = errors.New("units: bad [0-9]*") // never printed

// leadingInt consumes the leading [0-9]* from s.
func leadingInt(s string) (x int64, rem string, err error) {
	i := 0
	for ; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			break
		}
		if x >= (1<<63-10)/10 {
			// overflow
			return 0, "", errLeadingInt
		}
		x = x*10 + int64(c) - '0'
	}
	return x, s[i:], nil
}

func ParseUnit(s string, unitMap map[string]float64) (int64, error) {
	// [-+]?([0-9]*(\.[0-9]*)?[a-z]+)+
	orig := s
	f := float64(0)
	neg := false

	// Consume [-+]?
	if s != "" {
		c := s[0]
		if c == '-' || c == '+' {
			neg = c == '-'
			s = s[1:]
		}
	}
	// Special case: if all that is left is "0", this is zero.
	if s == "0" {
		return 0, nil
	}
	if s == "" {
		return 0, errors.New("units: invalid " + orig)
	}
	for s != "" {
		g := float64(0) // this element of the sequence

		var x int64
		var err error

		// The next character must be [0-9.]
		if !(s[0] == '.' || ('0' <= s[0] && s[0] <= '9')) {
			return 0, errors.New("units: invalid " + orig)
		}
		// Consume [0-9]*
		pl := len(s)
		x, s, err = leadingInt(s)
		if err != nil {
			return 0, errors.New("units: invalid " + orig)
		}
		g = float64(x)
		pre := pl != len(s) // whether we consumed anything before a period

		// Consume (\.[0-9]*)?
		post := false
		if s != "" && s[0] == '.' {
			s = s[1:]
			pl := len(s)
			x, s, err = leadingInt(s)
			if err != nil {
				return 0, errors.New("units: invalid " + orig)
			}
			scale := 1.0
			for n := pl - len(s); n > 0; n-- {
				scale *= 10
			}
			g += float64(x) / scale
			post = pl != len(s)
		}
		if !pre && !post {
			// no digits (e.g. ".s" or "-.s")
			return 0, errors.New("units: invalid " + orig)
		}

		// Consume unit.
		i := 0
		for ; i < len(s); i++ {
			c := s[i]
			if c == '.' || ('0' <= c && c <= '9') {
				break
			}
		}
		u := s[:i]
		s = s[i:]
		unit, ok := unitMap[u]
		if !ok {
			return 0, errors.New("units: unknown unit " + u + " in " + orig)
		}

		f += g * unit
	}

	if neg {
		f = -f
	}
	if f < float64(-1<<63) || f > float64(1<<63-1) {
		return 0, errors.New("units: overflow parsing unit")
	}
	return int64(f), nil
}
