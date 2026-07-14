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
	"strings"
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

	// prevWasComment tracks whether the last non-whitespace token emitted was a
	// comment. A structural "{" must never fold onto a line whose last token is
	// a comment, since "#" runs to end of line and would comment the brace out.
	prevWasComment := false
	// prevWasClose tracks whether the last non-whitespace token emitted was a
	// structural "}". A token that shared the source line with that "}" (other
	// than another "}" or a trailing comment) must break to its own indented
	// line rather than folding after the brace (I4).
	prevWasClose := false
	// foldedOpenAt, when >= 0, is the index of a structural "{" that was already
	// emitted early (before a trailing comment) as part of the address/comment/
	// brace fold; when the loop reaches that index it is skipped.
	foldedOpenAt := -1

	for i := range tokens {
		if i == foldedOpenAt {
			// This "{" was already emitted ahead of a trailing comment.
			continue
		}
		tk := tokens[i]
		isOpen := isOpenCurlyBrace(tk)
		// A structural close brace only closes a block when one is open. When
		// nesting is zero there is nothing to close (e.g. a "}" glued after a
		// backtick/quoted argument), so it is treated as an inline literal and
		// emitted verbatim at its source position.
		isClose := isCloseCurlyBrace(tk) && nesting > 0

		// A trailing comment shares its source line with the previous token
		// (e.g. after "}", after "{", or after a directive) and renders inline
		// on that line; a standalone comment sits alone on its own line.
		trailingComment := tk.isComment && wrote && !isNextOnNewLine(tokens[i-1], tk)

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
			// EXCEPTION: a standalone comment line must keep the following "{"
			// on its own line, otherwise the "#" would comment the brace out.
			if prevWasComment {
				breaks = 1
			} else {
				breaks = 0
			}
		case isClose:
			// A closing brace always goes on its own line, and dedents.
			if wrote && !atLineStart {
				breaks = 1
			}
			if nesting > 0 {
				nesting--
			}
		case trailingComment:
			// A trailing comment stays on the current line.
			breaks = 0
		}

		// A token that shared the source line with a preceding structural "}"
		// (other than another "}" or a trailing comment) breaks to its own
		// indented line instead of folding after the brace (I4).
		if prevWasClose && breaks == 0 && !isClose && !trailingComment {
			breaks = 1
		}

		// The content following an opening brace always begins on its own
		// indented line, regardless of how the source was laid out. This
		// applies to any token, including a nested opening brace. A trailing
		// comment after "{" is the exception: it stays inline on the "{" line.
		if wrote && isOpenCurlyBrace(tokens[i-1]) && breaks == 0 && !trailingComment {
			breaks = 1
		}

		// A blank line always follows a top-level closing brace, unless this
		// token is a comment trailing that brace on the same source line.
		if prevTopClose && breaks < 2 && !trailingComment {
			breaks = 2
		}
		prevTopClose = false

		// Address/comment/brace fold: when this is a trailing comment whose very
		// next token is a structural "{" that opens this line's block, emit the
		// "{" on the head line before the comment, so "addr # c"⏎"{" renders as
		// "addr { # c". This must happen before any newline is emitted.
		if trailingComment && i+1 < len(tokens) && isOpenCurlyBrace(tokens[i+1]) && breaks == 0 && !atLineStart {
			out.WriteByte(' ')
			out.WriteString(tokens[i+1].Raw())
			nesting++
			foldedOpenAt = i + 1
		}

		// Emit the vertical spacing.
		for breaks > 0 {
			newline()
			breaks--
		}

		// Emit indentation at the start of a line.
		if atLineStart {
			writeIndent()
		}

		// A line continuation renders as "\", a newline, then a hanging indent
		// of nesting+1 tabs before the token (instead of a single space). The
		// token's Raw() carries the source continuation framing ("\"+newline+
		// indentation) as a prefix, so it is stripped and re-emitted normalized.
		body := tk.Raw()
		if tk.continuation && !atLineStart {
			out.WriteString(" \\\n")
			for j := 0; j < nesting+1; j++ {
				out.WriteByte('\t')
			}
			body = strings.TrimLeft(strings.TrimPrefix(body, "\\"), " \t\r\n")
			atLineStart = false
		} else if !atLineStart {
			// Emit horizontal separation for same-line tokens: exactly one space
			// separates two tokens that share a line (including an attaching "{").
			// A structural close brace at nesting zero (an inline literal) stays
			// glued to its predecessor when the source had no space. A comment
			// glues to a preceding quoted/backtick/heredoc token only when no
			// space separated them ("x"#c); otherwise it takes a leading space.
			inlineClose := isCloseCurlyBrace(tk) && !isClose
			gluedComment := tk.isComment && tokens[i-1].Quoted() && !tk.precededBySpace
			if !(inlineClose && !tk.precededBySpace) && !gluedComment {
				out.WriteByte(' ')
			}
		}

		// Emit the token body verbatim.
		out.WriteString(body)
		wrote = true
		atLineStart = false
		prevWasComment = tk.isComment
		prevWasClose = isClose

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
