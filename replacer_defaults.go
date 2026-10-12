// Copyright 2026 The Caddy Authors
// Licensed under the Apache License, Version 2.0.

package caddy

import (
	"fmt"
	"strings"

	"github.com/caddyserver/caddy/v2/internal/placeholder"
)

// ResolvePlaceholder resolves exactly one complete placeholder expression.
// Unlike Get, it understands {key:-default}: the default is selected when key
// is unknown or its value's string representation is empty. Defaults can contain
// nested placeholders and are evaluated only when selected. Provider values are
// never evaluated as placeholder expressions.
//
// Primary values and defaults consisting of a single placeholder retain their
// Go type. Literal and composite defaults produce strings, except that an
// error-valued nested reference stops composition and retains its type.
// The boolean reports
// whether the selected placeholder is known; an explicit literal default is
// always known, including an empty default. Unknown references in composite
// defaults remain literal, as with ReplaceKnown.
//
// Get continues to perform exact lookup, including keys containing :-.
func (r *Replacer) ResolvePlaceholder(input string) (any, bool, error) {
	ref, n, err := placeholder.Parse(input)
	if err != nil {
		return nil, false, err
	}
	if n == 0 || n != len(input) {
		return nil, false, fmt.Errorf("expected a single placeholder expression")
	}
	resolved, err := r.resolveReference(ref, replacementPolicy{}, 0)
	return resolved.value, resolved.found, err
}

type replacementPolicy struct {
	treatUnknownAsEmpty, errOnEmpty, errOnUnknown bool
}

type resolvedPlaceholder struct {
	value      any
	found      bool
	name       string
	defaulted  bool
	unresolved string
}

func (r *Replacer) resolveReference(ref placeholder.Reference, policy replacementPolicy, depth int) (resolvedPlaceholder, error) {
	if depth >= placeholder.MaxDepth {
		return resolvedPlaceholder{}, fmt.Errorf("placeholder default exceeds maximum depth of %d", placeholder.MaxDepth)
	}
	key := placeholder.UnescapeKey(ref.Key)
	value, found := r.Get(key)
	resolved := resolvedPlaceholder{value: value, found: found, name: key}
	if !found && !policy.treatUnknownAsEmpty {
		resolved.unresolved = "{" + ref.Key + "}"
	}
	if !ref.HasDefault || (found && ToString(value) != "") {
		return resolved, nil
	}

	// Preserve both the type and source of a sole nested reference. In particular,
	// query rewriting needs to distinguish an already-escaped query from literal
	// fallback text. Composite defaults have no single source placeholder.
	nested, n, err := placeholder.Parse(ref.Default)
	if err != nil {
		return resolvedPlaceholder{}, err
	}
	if n > 0 && n == len(ref.Default) {
		selected, err := r.resolveReference(nested, policy, depth+1)
		selected.defaulted = true
		return selected, err
	}
	selected, err := r.expandDefault(ref.Default, policy, depth+1)
	selected.defaulted = true
	return selected, err
}

// expandDefault only scans configured fallback text. It does not invoke the
// caller's transformation or empty-value substitution on intermediate values.
func (r *Replacer) expandDefault(input string, policy replacementPolicy, depth int) (resolvedPlaceholder, error) {
	var out strings.Builder
	out.Grow(len(input))
	for i := 0; i < len(input); i++ {
		if input[i] == '\\' && i+1 < len(input) && strings.ContainsRune("{}\\", rune(input[i+1])) {
			i++
			out.WriteByte(input[i])
			continue
		}
		if input[i] != '{' {
			out.WriteByte(input[i])
			continue
		}
		ref, n, err := placeholder.Parse(input[i:])
		if err != nil {
			return resolvedPlaceholder{}, err
		}
		if n == 0 {
			out.WriteString(input[i:])
			break
		}
		resolved, err := r.resolveReference(ref, policy, depth)
		if err != nil {
			return resolvedPlaceholder{}, err
		}
		if !resolved.found {
			if policy.errOnUnknown {
				return resolvedPlaceholder{}, fmt.Errorf("unrecognized placeholder {%s}", resolved.name)
			}
			if !policy.treatUnknownAsEmpty {
				out.WriteString(resolved.unresolved)
			}
		} else {
			// Error values may carry control-flow information, such as an HTTP
			// body-limit status. Do not hide their type in composite text.
			if _, ok := resolved.value.(error); ok {
				return resolved, nil
			}
			text := ToString(resolved.value)
			if text == "" && policy.errOnEmpty {
				return resolvedPlaceholder{}, fmt.Errorf("evaluated placeholder {%s} is empty", resolved.name)
			}
			out.WriteString(text)
		}
		i += n - 1
	}
	return resolvedPlaceholder{value: out.String(), found: true}, nil
}
