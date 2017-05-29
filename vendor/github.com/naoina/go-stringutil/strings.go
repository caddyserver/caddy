package stringutil

import (
	"sync"
	"unicode"
	"unicode/utf8"
)

var (
	mu sync.Mutex

	// Based on https://github.com/golang/lint/blob/32a87160691b3c96046c0c678fe57c5bef761456/lint.go#L702
	commonInitialismMap = map[string]struct{}{
		"API":   struct{}{},
		"ASCII": struct{}{},
		"CPU":   struct{}{},
		"CSRF":  struct{}{},
		"CSS":   struct{}{},
		"DNS":   struct{}{},
		"EOF":   struct{}{},
		"GUID":  struct{}{},
		"HTML":  struct{}{},
		"HTTP":  struct{}{},
		"HTTPS": struct{}{},
		"ID":    struct{}{},
		"IP":    struct{}{},
		"JSON":  struct{}{},
		"LHS":   struct{}{},
		"QPS":   struct{}{},
		"RAM":   struct{}{},
		"RHS":   struct{}{},
		"RPC":   struct{}{},
		"SLA":   struct{}{},
		"SMTP":  struct{}{},
		"SQL":   struct{}{},
		"SSH":   struct{}{},
		"TCP":   struct{}{},
		"TLS":   struct{}{},
		"TTL":   struct{}{},
		"UDP":   struct{}{},
		"UI":    struct{}{},
		"UID":   struct{}{},
		"UUID":  struct{}{},
		"URI":   struct{}{},
		"URL":   struct{}{},
		"UTF8":  struct{}{},
		"VM":    struct{}{},
		"XML":   struct{}{},
		"XSRF":  struct{}{},
		"XSS":   struct{}{},
	}
	commonInitialisms = keys(commonInitialismMap)
	commonInitialism  = mustDoubleArray(newDoubleArray(commonInitialisms))
	longestLen        = longestLength(commonInitialisms)
	shortestLen       = shortestLength(commonInitialisms, longestLen)
)

// ToUpperCamelCase returns a copy of the string s with all Unicode letters mapped to their camel case.
// It will convert to upper case previous letter of '_' and first letter, and remove letter of '_'.
func ToUpperCamelCase(s string) string {
	if s == "" {
		return ""
	}
	upper := true
	start := 0
	result := make([]byte, 0, len(s))
	var runeBuf [utf8.UTFMax]byte
	var initialism []byte
	for _, c := range s {
		if c == '_' {
			upper = true
			candidate := string(result[start:])
			initialism = initialism[:0]
			for _, r := range candidate {
				if r < utf8.RuneSelf {
					initialism = append(initialism, toUpperASCII(byte(r)))
				} else {
					n := utf8.EncodeRune(runeBuf[:], unicode.ToUpper(r))
					initialism = append(initialism, runeBuf[:n]...)
				}
			}
			if length := commonInitialism.LookupByBytes(initialism); length > 0 {
				result = append(result[:start], initialism...)
			}
			start = len(result)
			continue
		}
		if upper {
			if c < utf8.RuneSelf {
				result = append(result, toUpperASCII(byte(c)))
			} else {
				n := utf8.EncodeRune(runeBuf[:], unicode.ToUpper(c))
				result = append(result, runeBuf[:n]...)
			}
			upper = false
			continue
		}
		if c < utf8.RuneSelf {
			result = append(result, byte(c))
		} else {
			n := utf8.EncodeRune(runeBuf[:], c)
			result = append(result, runeBuf[:n]...)
		}
	}
	candidate := string(result[start:])
	initialism = initialism[:0]
	for _, r := range candidate {
		if r < utf8.RuneSelf {
			initialism = append(initialism, toUpperASCII(byte(r)))
		} else {
			n := utf8.EncodeRune(runeBuf[:], unicode.ToUpper(r))
			initialism = append(initialism, runeBuf[:n]...)
		}
	}
	if length := commonInitialism.LookupByBytes(initialism); length > 0 {
		result = append(result[:start], initialism...)
	}
	return string(result)
}

// ToUpperCamelCaseASCII is similar to ToUpperCamelCase, but optimized for
// only the ASCII characters.
// ToUpperCamelCaseASCII is faster than ToUpperCamelCase, but doesn't work if
// contains non-ASCII characters.
func ToUpperCamelCaseASCII(s string) string {
	if s == "" {
		return ""
	}
	upper := true
	start := 0
	result := make([]byte, 0, len(s))
	var initialism []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '_' {
			upper = true
			candidate := result[start:]
			initialism = initialism[:0]
			for _, b := range candidate {
				initialism = append(initialism, toUpperASCII(b))
			}
			if length := commonInitialism.LookupByBytes(initialism); length > 0 {
				result = append(result[:start], initialism...)
			}
			start = len(result)
			continue
		}
		if upper {
			result = append(result, toUpperASCII(c))
			upper = false
			continue
		}
		result = append(result, c)
	}
	candidate := result[start:]
	initialism = initialism[:0]
	for _, b := range candidate {
		initialism = append(initialism, toUpperASCII(b))
	}
	if length := commonInitialism.LookupByBytes(initialism); length > 0 {
		result = append(result[:start], initialism...)
	}
	return string(result)
}

// ToSnakeCase returns a copy of the string s with all Unicode letters mapped to their snake case.
// It will insert letter of '_' at position of previous letter of uppercase and all
// letters convert to lower case.
// ToSnakeCase does not insert '_' letter into a common initialism word like ID, URL and so on.
func ToSnakeCase(s string) string {
	if s == "" {
		return ""
	}
	result := make([]byte, 0, len(s))
	var runeBuf [utf8.UTFMax]byte
	var j, skipCount int
	for i, c := range s {
		if i < skipCount {
			continue
		}
		if unicode.IsUpper(c) {
			if i != 0 {
				result = append(result, '_')
			}
			next := nextIndex(j, len(s))
			if length := commonInitialism.Lookup(s[j:next]); length > 0 {
				for _, r := range s[j : j+length] {
					if r < utf8.RuneSelf {
						result = append(result, toLowerASCII(byte(r)))
					} else {
						n := utf8.EncodeRune(runeBuf[:], unicode.ToLower(r))
						result = append(result, runeBuf[:n]...)
					}
				}
				j += length - 1
				skipCount = i + length
				continue
			}
		}
		if c < utf8.RuneSelf {
			result = append(result, toLowerASCII(byte(c)))
		} else {
			n := utf8.EncodeRune(runeBuf[:], unicode.ToLower(c))
			result = append(result, runeBuf[:n]...)
		}
		j++
	}
	return string(result)
}

// ToSnakeCaseASCII is similar to ToSnakeCase, but optimized for only the ASCII
// characters.
// ToSnakeCaseASCII is faster than ToSnakeCase, but doesn't work correctly if
// contains non-ASCII characters.
func ToSnakeCaseASCII(s string) string {
	if s == "" {
		return ""
	}
	result := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isUpperASCII(c) {
			if i != 0 {
				result = append(result, '_')
			}
			if k := i + shortestLen - 1; k < len(s) && isUpperASCII(s[k]) {
				if length := commonInitialism.Lookup(s[i:nextIndex(i, len(s))]); length > 0 {
					for j, buf := 0, s[i:i+length]; j < len(buf); j++ {
						result = append(result, toLowerASCII(buf[j]))
					}
					i += length - 1
					continue
				}
			}
		}
		result = append(result, toLowerASCII(c))
	}
	return string(result)
}

// AddCommonInitialism adds ss to list of common initialisms.
func AddCommonInitialism(ss ...string) {
	mu.Lock()
	defer mu.Unlock()
	for _, s := range ss {
		commonInitialismMap[s] = struct{}{}
	}
	commonInitialisms = keys(commonInitialismMap)
	commonInitialism = mustDoubleArray(newDoubleArray(commonInitialisms))
	longestLen = longestLength(commonInitialisms)
	shortestLen = shortestLength(commonInitialisms, longestLen)
}

// DelCommonInitialism deletes ss from list of common initialisms.
func DelCommonInitialism(ss ...string) {
	mu.Lock()
	defer mu.Unlock()
	for _, s := range ss {
		delete(commonInitialismMap, s)
	}
	commonInitialisms = keys(commonInitialismMap)
	commonInitialism = mustDoubleArray(newDoubleArray(commonInitialisms))
	longestLen = longestLength(commonInitialisms)
	shortestLen = shortestLength(commonInitialisms, longestLen)
}

func isUpperASCII(c byte) bool {
	return 'A' <= c && c <= 'Z'
}

func isLowerASCII(c byte) bool {
	return 'a' <= c && c <= 'z'
}

func toUpperASCII(c byte) byte {
	if isLowerASCII(c) {
		return c - ('a' - 'A')
	}
	return c
}

func toLowerASCII(c byte) byte {
	if isUpperASCII(c) {
		return c + 'a' - 'A'
	}
	return c
}

func nextIndex(i, maxlen int) int {
	if n := i + longestLen; n < maxlen {
		return n
	}
	return maxlen
}

func keys(m map[string]struct{}) []string {
	result := make([]string, 0, len(m))
	for k := range m {
		result = append(result, k)
	}
	return result
}

func shortestLength(strs []string, shortest int) int {
	for _, s := range strs {
		if candidate := utf8.RuneCountInString(s); candidate < shortest {
			shortest = candidate
		}
	}
	return shortest
}

func longestLength(strs []string) (longest int) {
	for _, s := range strs {
		if candidate := utf8.RuneCountInString(s); candidate > longest {
			longest = candidate
		}
	}
	return longest
}
