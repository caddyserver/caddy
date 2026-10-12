// Copyright 2026 The Caddy Authors
// Licensed under the Apache License, Version 2.0.

// Package placeholder handles the syntax of placeholder references without
// evaluating values. Providers and replacement policies belong to the caller.
package placeholder

import (
	"fmt"
	"strings"
)

// MaxDepth is the maximum number of nested braces in a default expression,
// including the outer reference.
const MaxDepth = 32

// Reference is one placeholder's key and optional unevaluated default.
type Reference struct {
	Key        string
	Default    string
	HasDefault bool
}

// Parse reads a reference at the start of input and returns its byte length.
// A non-reference or unclosed ordinary reference returns zero length without an
// error. Ordinary references retain the legacy first-closing-brace convention.
// Defaults use balanced braces and reserve an unescaped :- after a nonempty key.
// An opening brace or double quote in the key disables default syntax, so JSON
// and legacy keys are not accidentally interpreted as default expressions.
func Parse(input string) (Reference, int, error) {
	if len(input) == 0 || input[0] != '{' {
		return Reference{}, 0, nil
	}
	// Ordinary references are by far the common case. Use the optimized
	// string scans without examining the remainder of the template: searching
	// the entire suffix for a default operator at every reference is quadratic.
	if end := strings.IndexByte(input, '}'); end > 0 &&
		(input[end-1] != '\\' || end == len(input)-1) &&
		!strings.Contains(input[1:end], ":-") {
		return Reference{Key: input[1:end]}, end + 1, nil
	}
	eligible := true
	for i := 1; i < len(input); i++ {
		switch input[i] {
		case '{', '"':
			eligible = false
		case '}':
			// Historically a final closing brace terminates the reference
			// even when preceded by a backslash.
			if input[i-1] != '\\' || i == len(input)-1 {
				return Reference{Key: input[1:i]}, i + 1, nil
			}
		case ':':
			if eligible && i > 1 && i+1 < len(input) && input[i+1] == '-' && input[i-1] != '\\' {
				end, err := defaultEnd(input, i+2)
				if err != nil {
					return Reference{}, 0, err
				}
				return Reference{Key: input[1:i], Default: input[i+2 : end], HasDefault: true}, end + 1, nil
			}
		}
	}
	return Reference{}, 0, nil
}

func defaultEnd(input string, start int) (int, error) {
	depth := 1
	for i := start; i < len(input); i++ {
		if input[i] == '\\' && i+1 < len(input) && strings.ContainsRune("{}\\", rune(input[i+1])) {
			i++
			continue
		}
		switch input[i] {
		case '{':
			depth++
			if depth > MaxDepth {
				return 0, fmt.Errorf("placeholder default exceeds maximum depth of %d", MaxDepth)
			}
		case '}':
			depth--
			if depth == 0 {
				return i, nil
			}
		}
	}
	return 0, fmt.Errorf("unclosed placeholder default")
}

// UnescapeKey removes the backslash protecting the reserved default operator.
// Other backslashes remain part of the exact provider key.
func UnescapeKey(key string) string {
	return strings.ReplaceAll(key, `\:-`, ":-")
}

// RewriteKeys rewrites reference keys, including keys inside defaults. Literal
// text and escape sequences are preserved byte for byte.
func RewriteKeys(input string, rewrite func(string) string) (string, error) {
	return rewriteInput(input, func(raw string, ref Reference) (string, error) {
		key := rewrite(ref.Key)
		if !ref.HasDefault {
			return "{" + key + "}", nil
		}
		fallback, err := RewriteKeys(ref.Default, rewrite)
		if err != nil {
			return "", err
		}
		return "{" + key + ":-" + fallback + "}", nil
	})
}

// RewriteTokens rewrites each complete reference. The callback receives the raw
// reference including its braces; nested defaults belong to that token. Legacy
// spans containing nested opening braces are scanned for their inner references.
// Literal text and escape sequences are preserved byte for byte.
func RewriteTokens(input string, rewrite func(string) string) (string, error) {
	return rewriteInput(input, func(raw string, _ Reference) (string, error) {
		return rewrite(raw), nil
	})
}

func rewriteInput(input string, rewrite func(string, Reference) (string, error)) (string, error) {
	var out strings.Builder
	last := 0
	for i := 0; i < len(input); i++ {
		if input[i] == '\\' && i+1 < len(input) && strings.ContainsRune("{}\\", rune(input[i+1])) {
			i++
			continue
		}
		if input[i] != '{' {
			continue
		}
		ref, n, err := Parse(input[i:])
		if err != nil {
			return "", err
		}
		if n == 0 {
			// Parse examined the remaining suffix. Avoid repeatedly scanning
			// unmatched braces in adversarial input.
			break
		}
		if !ref.HasDefault {
			// A legacy outer reference can include JSON or malformed braces.
			// Its inner references still need rewriting. Jump to the first
			// default expression or the innermost ordinary reference rather
			// than parsing every intervening open, which would be quadratic.
			inner := -1
			eligible := false
			for j := 0; j < len(ref.Key); j++ {
				if ref.Key[j] == '\\' && j+1 < len(ref.Key) && strings.ContainsRune("{}\\", rune(ref.Key[j+1])) {
					j++
					continue
				}
				if ref.Key[j] == '{' {
					inner = j
					eligible = true
				}
				if ref.Key[j] == '"' {
					eligible = false
				}
				if eligible && j > inner+1 && ref.Key[j] == ':' && j+1 < len(ref.Key) && ref.Key[j+1] == '-' && ref.Key[j-1] != '\\' {
					break
				}
			}
			if inner >= 0 {
				i += inner
				// The loop increments i to the selected inner opening brace.
				continue
			}
		}
		replacement, err := rewrite(input[i:i+n], ref)
		if err != nil {
			return "", err
		}
		out.WriteString(input[last:i])
		out.WriteString(replacement)
		i += n - 1
		last = i + 1
	}
	if last == 0 {
		return input, nil
	}
	out.WriteString(input[last:])
	return out.String(), nil
}
