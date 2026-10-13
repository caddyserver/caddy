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

// String returns the reference's syntax, preserving its key and default text.
func (ref Reference) String() string {
	if ref.HasDefault {
		return "{" + ref.Key + ":-" + ref.Default + "}"
	}
	return "{" + ref.Key + "}"
}

// ParseSingle reads exactly one complete reference. A non-reference or input
// with trailing text returns false; malformed defaults return an error.
func ParseSingle(input string) (Reference, bool, error) {
	ref, n, err := Parse(input)
	return ref, n > 0 && n == len(input), err
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
	end := strings.IndexByte(input, '}')
	if end < 0 && !strings.Contains(input, ":-") {
		return Reference{}, 0, nil
	}
	if end > 0 &&
		(input[end-1] != '\\' || end == len(input)-1) &&
		(input[1] == '{' || input[1] == '"' || !strings.Contains(input[1:end], ":-")) {
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
	return rewriteKeys(input, rewrite, false)
}

func rewriteKeys(input string, rewrite func(string) string, inDefault bool) (string, error) {
	return rewriteInput(input, inDefault, func(raw string, ref Reference) (string, error) {
		ref.Key = rewrite(ref.Key)
		if ref.HasDefault {
			fallback, err := rewriteKeys(ref.Default, rewrite, true)
			if err != nil {
				return "", err
			}
			ref.Default = fallback
		}
		return ref.String(), nil
	})
}

// Walk visits references in source order, including references inside defaults.
// Escaped references are skipped. Legacy spans containing nested opening braces
// are scanned for their inner references, as with RewriteTokens.
func Walk(input string, visit func(Reference) error) error {
	return walkInput(input, visit, false)
}

func walkInput(input string, visit func(Reference) error, inDefault bool) error {
	return scanInput(input, inDefault, func(_, _ int, ref Reference) error {
		if err := visit(ref); err != nil {
			return err
		}
		if ref.HasDefault {
			return walkInput(ref.Default, visit, true)
		}
		return nil
	})
}

// Names returns each visited reference's normalized provider key in source order.
func Names(input string) ([]string, error) {
	var names []string
	err := Walk(input, func(ref Reference) error {
		names = append(names, UnescapeKey(ref.Key))
		return nil
	})
	if err != nil {
		return nil, err
	}
	return names, nil
}

// RewriteTokens rewrites each complete reference. The callback receives the raw
// reference including its braces; nested defaults belong to that token. Legacy
// spans containing nested opening braces are scanned for their inner references.
// Literal text and escape sequences are preserved byte for byte.
func RewriteTokens(input string, rewrite func(string) string) (string, error) {
	return rewriteInput(input, false, func(raw string, _ Reference) (string, error) {
		return rewrite(raw), nil
	})
}

func rewriteInput(input string, inDefault bool, rewrite func(string, Reference) (string, error)) (string, error) {
	var out strings.Builder
	last := 0
	err := scanInput(input, inDefault, func(start, end int, ref Reference) error {
		replacement, err := rewrite(input[start:end], ref)
		if err != nil {
			return err
		}
		out.WriteString(input[last:start])
		out.WriteString(replacement)
		last = end
		return nil
	})
	if err != nil {
		return "", err
	}
	if last == 0 {
		return input, nil
	}
	out.WriteString(input[last:])
	return out.String(), nil
}

// scanInput supplies complete references and their byte spans without allocating
// replacement text. All syntax visitors share this scanner.
// Outside defaults, a preceding backslash always protects an opening brace,
// matching legacy replacement. Default text uses paired backslash escapes.
func scanInput(input string, inDefault bool, visit func(int, int, Reference) error) error {
	for i := 0; i < len(input); i++ {
		if inDefault && input[i] == '\\' && i+1 < len(input) && strings.ContainsRune("{}\\", rune(input[i+1])) {
			i++
			continue
		}
		if input[i] != '{' || (!inDefault && i > 0 && input[i-1] == '\\') {
			continue
		}
		ref, n, err := Parse(input[i:])
		if err != nil {
			return err
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
				if inDefault && ref.Key[j] == '\\' && j+1 < len(ref.Key) && strings.ContainsRune("{}\\", rune(ref.Key[j+1])) {
					j++
					continue
				}
				if ref.Key[j] == '{' && (inDefault || j == 0 || ref.Key[j-1] != '\\') {
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
		if err := visit(i, i+n, ref); err != nil {
			return err
		}
		i += n - 1
	}
	return nil
}
