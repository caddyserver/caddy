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

package caddyfile

import (
	"bytes"
)

// Format formats the input Caddyfile to a standard, nice-looking appearance.
// It tokenizes the input in format mode and renders the token stream, taking
// control over bracing, indentation, and whitespace; token bodies (words,
// comments, placeholders, quoted/backtick strings, heredocs, and escaped
// characters) are emitted verbatim.
func Format(input []byte) []byte {
	return FormatWithOptions(input, FormatOptions{})
}

// FormatOptions configures optional formatting behavior.
type FormatOptions struct {
	// WrapUnbracedSite, when true, wraps a single unbraced site block in braces
	// (Phase 3). Default false.
	WrapUnbracedSite bool
}

// FormatWithOptions formats the input Caddyfile with the given options.
func FormatWithOptions(input []byte, opts FormatOptions) []byte {
	tokens, err := Lex(input, "", LexOptions{Comments: true, Raw: true})
	if err != nil {
		// On a lex error, fall back to the trimmed input with a trailing newline;
		// Format never panics (Invariant 3).
		trimmed := bytes.TrimSpace(input)
		return append(trimmed, '\n')
	}
	// opts.WrapUnbracedSite is wired in Phase 3 (Task 19); ignored here.
	_ = opts.WrapUnbracedSite
	return formatTokens(tokens)
}

// formatTokens renders a format-mode token stream (as produced by
// Lex(..., LexOptions{Comments: true, Raw: true})) into a normalized
// Caddyfile. It controls all indentation and structural whitespace; token
// bodies are emitted verbatim via Token.Raw().
func formatTokens(tokens []Token) []byte {
	var out bytes.Buffer

	nesting := 0        // current indentation level
	atLineStart := true // whether the cursor is at the start of a fresh line
	wrote := false      // whether any non-whitespace has been written yet
	prevTopClose := false

	writeIndent := func() {
		for i := 0; i < nesting; i++ {
			out.WriteByte('\t')
		}
	}

	newline := func() {
		out.WriteByte('\n')
		atLineStart = true
	}

	for i := range tokens {
		tk := tokens[i]
		isOpen := isOpenCurlyBrace(tk)
		// A structural close brace only closes a block when one is open. When
		// nesting is zero there is nothing to close (e.g. a "}" glued after a
		// backtick/quoted argument), so it is treated as an inline literal and
		// emitted verbatim at its source position.
		isClose := isCloseCurlyBrace(tk) && nesting > 0

		// breaks is the number of newlines to emit before this token:
		//   0 = stay on the current line, 1 = new line, 2 = one blank line.
		breaks := 0
		if wrote {
			prev := tokens[i-1]
			if isNextOnNewLine(prev, tk) {
				breaks = 1
				// A gap of two or more lines yields at most one blank line.
				if tk.Line-(prev.Line+prev.NumLineBreaks()) >= 2 {
					breaks = 2
				}
			}
		}

		switch {
		case isOpen:
			// An opening brace attaches to the current line: never break to a
			// new line before it (it joins the preceding token with a space).
			breaks = 0
		case isClose:
			// A closing brace always goes on its own line, and dedents.
			if wrote && !atLineStart {
				breaks = 1
			}
			if nesting > 0 {
				nesting--
			}
		}

		// The content following an opening brace always begins on its own
		// indented line, regardless of how the source was laid out. This
		// applies to any token, including a nested opening brace.
		if wrote && isOpenCurlyBrace(tokens[i-1]) && breaks == 0 {
			breaks = 1
		}

		// A blank line always follows a top-level closing brace.
		if prevTopClose && breaks < 2 {
			breaks = 2
		}
		prevTopClose = false

		// Emit the vertical spacing.
		for breaks > 0 {
			newline()
			breaks--
		}

		// Emit indentation at the start of a line.
		if atLineStart {
			writeIndent()
		}

		// Emit horizontal separation for same-line tokens: exactly one space
		// separates two tokens that share a line (including an attaching "{").
		// A structural close brace at nesting zero (an inline literal, see
		// above) stays glued to its predecessor when the source had no space.
		if !atLineStart {
			inlineClose := isCloseCurlyBrace(tk) && !isClose
			if !(inlineClose && !tk.precededBySpace) {
				out.WriteByte(' ')
			}
		}

		// Emit the token body verbatim.
		out.WriteString(tk.Raw())
		wrote = true
		atLineStart = false

		// Structural bookkeeping after emitting. Vertical spacing after a
		// brace is produced by the next token's break calculation, so we don't
		// emit trailing newlines here.
		if isOpen {
			nesting++
		} else if isClose && nesting == 0 {
			prevTopClose = true
		}
	}

	// Trim leading/trailing whitespace, then ensure exactly one trailing
	// newline (newlines are significant to Caddyfile syntax).
	trimmed := bytes.TrimSpace(out.Bytes())
	return append(trimmed, '\n')
}
