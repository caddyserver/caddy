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
	// Some token shapes cannot be rendered without changing what they lex back
	// to, which would break idempotency. When one is present, preserve the
	// trimmed input verbatim instead of re-rendering; this is trivially
	// idempotent since a second pass hits the same condition.
	//
	// The mandatory trailing newline is the subtle case: if appending it changes
	// how the input tokenizes (an unterminated or escaped quote, or a dangling
	// escape, that swallows the newline into a token), then no rendering is a
	// fixed point. Detect that here so Format falls back to the trimmed input;
	// trimming removes the trailing newline again, so the fallback is stable.
	if hasUnformattableToken(tokens) || trailingNewlineChangesTokens(input) {
		trimmed := bytes.TrimSpace(input)
		return append(trimmed, '\n')
	}
	// opts.WrapUnbracedSite is wired in Phase 3 (Task 19); ignored here.
	_ = opts.WrapUnbracedSite
	out := formatTokens(tokens)

	// Backstop: formatting must be idempotent and must not change the token
	// stream (only structural whitespace). Re-lex the output and require both
	// that its token texts match the input's and that re-rendering it reproduces
	// it exactly (a fixed point). If some pathological escape/whitespace
	// combination the checks above did not anticipate slips through — changing a
	// token or leaving the vertical spacing unstable — fall back to preserving
	// the trimmed input verbatim. Well-formed input is a fixed point on the first
	// pass, so this only affects degenerate input. A lex error on the output is
	// likewise treated as a divergence.
	reToks, rerr := Lex(out, "", LexOptions{Comments: true, Raw: true})
	if rerr != nil || !sameTokenTexts(tokens, reToks) ||
		!bytes.Equal(out, formatTokens(reToks)) {
		trimmed := bytes.TrimSpace(input)
		return append(trimmed, '\n')
	}
	return out
}

// trailingNewlineChangesTokens reports whether appending a newline to input
// changes its format-mode token-text sequence. This is true for inputs whose
// final token would swallow Format's mandatory trailing newline — an
// unterminated or escaped quote/backtick, or a dangling escape at EOF — for
// which no rendering can be a fixed point. Inputs already ending in a newline,
// and well-formed inputs, are unaffected.
func trailingNewlineChangesTokens(input []byte) bool {
	if n := len(input); n > 0 && input[n-1] == '\n' {
		return false
	}
	a, erra := Lex(input, "", LexOptions{Comments: true, Raw: true})
	withNL := make([]byte, len(input)+1)
	copy(withNL, input)
	withNL[len(input)] = '\n'
	b, errb := Lex(withNL, "", LexOptions{Comments: true, Raw: true})
	if erra != nil || errb != nil {
		return erra != errb
	}
	return !sameTokenTexts(a, b)
}

// sameTokenTexts reports whether two token streams have the same sequence of
// token texts, ignoring comment tokens (comment whitespace is intentionally
// normalized by the formatter).
func sameTokenTexts(a, b []Token) bool {
	ai, bi := 0, 0
	for {
		for ai < len(a) && a[ai].isComment {
			ai++
		}
		for bi < len(b) && b[bi].isComment {
			bi++
		}
		if ai >= len(a) || bi >= len(b) {
			return ai >= len(a) && bi >= len(b)
		}
		if a[ai].Text != b[bi].Text {
			return false
		}
		ai++
		bi++
	}
}

// hasUnformattableToken reports whether the token stream contains a token whose
// rendering cannot be made idempotent, so Format falls back to preserving the
// input verbatim. Two shapes qualify:
//
//   - An ambiguous heredoc opener: a regular (unquoted, non-comment) token whose
//     verbatim source is a valid heredoc opener shape ("<<MARKER") and which is
//     the last token on its source line. It stays literal in the source only
//     because trailing space separated it from the newline; the formatter drops
//     that space, so the rendered output would re-lex as a real heredoc opener
//     and glue in the following line. (An escaped opener "\<<MARKER" re-lexes as
//     a regular token and is unaffected, so only a bare "<<MARKER" qualifies.)
//   - An unterminated quote/backtick: a token whose verbatim source begins with
//     a quote or backtick but which is not marked Quoted (the closing delimiter
//     was never seen). It swallowed the rest of the input; rendering it and
//     appending the mandatory trailing newline changes what it lexes back to.
//   - A dangling escape: a token whose verbatim source ends in an unpaired
//     backslash (an odd run of trailing backslashes). Appending the mandatory
//     trailing newline turns it into a line continuation, chaining in the next
//     line on re-lex.
//   - A leading line continuation: the first token carries continuation framing
//     ("\"+newline) even though there is no preceding token to continue from.
//     Its anchoring Line sits a line before its rendered content, so the
//     vertical-spacing math for the following token is unstable across passes.
func hasUnformattableToken(tokens []Token) bool {
	for i, tk := range tokens {
		if tk.isComment {
			continue
		}
		// Leading dangling line continuation on the first non-comment token.
		if !anyNonCommentBefore(tokens, i) && tk.continuation {
			return true
		}
		// Messy line continuation: continuation framing whose backslash is not
		// immediately followed by the newline (e.g. "\"+vertical-tab+newline). The
		// formatter's continuation normalization cannot cleanly strip the stray
		// whitespace, so the token text shifts on re-lex.
		if tk.continuation && hasMessyContinuationFraming(tk.Raw()) {
			return true
		}
		raw := tk.Raw()
		// A quote or backtick embedded in a literal (non-Quoted) token: the token
		// only stayed unquoted because the delimiter was escaped or never closed,
		// so its text and the formatter's spacing around it are sensitive to the
		// mandatory trailing newline and cannot be rendered idempotently. (Quotes
		// inside a properly Quoted token have wasQuoted != 0 and are unaffected.)
		if tk.wasQuoted == 0 && strings.ContainsAny(raw, "\"`") {
			return true
		}
		// Dangling (unpaired) trailing backslash.
		if tk.wasQuoted == 0 && endsInDanglingBackslash(raw) {
			return true
		}
		if tk.wasQuoted != 0 {
			continue
		}
		// Ambiguous heredoc opener.
		if !strings.HasPrefix(raw, "<<") || len(raw) <= 2 {
			continue
		}
		marker := raw[2:]
		if !heredocMarkerRegexp.MatchString(marker) {
			continue
		}
		if i+1 >= len(tokens) || fmtNextOnNewLine(tk, tokens[i+1]) {
			return true
		}
	}
	return false
}

// anyNonCommentBefore reports whether any token before index i is not a comment.
func anyNonCommentBefore(tokens []Token, i int) bool {
	for j := 0; j < i; j++ {
		if !tokens[j].isComment {
			return true
		}
	}
	return false
}

// hasMessyContinuationFraming reports whether raw begins (after any leading
// whitespace) with a line-continuation backslash that is not immediately
// followed by a newline — i.e. there is stray whitespace between the "\" and the
// newline (e.g. "\"+vertical-tab+newline). A clean continuation has "\" directly
// before the newline.
func hasMessyContinuationFraming(raw string) bool {
	s := strings.TrimLeft(raw, " \t\r\n\v\f")
	if !strings.HasPrefix(s, `\`) {
		return false
	}
	rest := s[1:]
	return len(rest) > 0 && rest[0] != '\n' && rest[0] != '\r'
}

// endsInDanglingBackslash reports whether s ends in an odd (unpaired) run of
// backslashes, i.e. a trailing escape with nothing to escape. Trailing
// whitespace and newlines are ignored so that a backslash immediately before a
// (possibly appended) newline still counts: such a backslash forms a line
// continuation on re-lex, which is exactly the shape Format must not introduce.
func endsInDanglingBackslash(s string) bool {
	end := len(s)
	for end > 0 {
		c := s[end-1]
		if c == '\n' || c == '\r' || c == ' ' || c == '\t' || c == '\v' || c == '\f' {
			end--
			continue
		}
		break
	}
	n := 0
	for i := end - 1; i >= 0 && s[i] == '\\'; i-- {
		n++
	}
	return n%2 == 1
}

// fmtNumLineBreaks returns how many physical line breaks a token spans, for use
// in format-mode vertical-spacing decisions. For quoted tokens (double-quote,
// backtick, and heredoc) it counts the newlines in the verbatim source (Raw)
// rather than deriving the count from the processed Text. Raw is the exact
// physical span, so this correctly handles an empty-bodied heredoc ("<<E\nE",
// which Token.NumLineBreaks over-counts by always adding two) and a quoted token
// whose Raw carries a leading line-continuation newline (e.g. "\\\n`...`", which
// Token.NumLineBreaks under-counts); both otherwise place a following token on
// the wrong line and break idempotency. Unquoted tokens keep Token.NumLineBreaks
// (their Raw may carry "\"+newline continuation framing whose newline belongs to
// the token's anchoring Line, not to its span).
func fmtNumLineBreaks(t Token) int {
	if t.wasQuoted != 0 {
		return strings.Count(t.Raw(), "\n")
	}
	return t.NumLineBreaks()
}

// fmtNextOnNewLine mirrors isNextOnNewLine but uses fmtNumLineBreaks so that
// empty-bodied heredocs are measured by their true line span in format mode.
func fmtNextOnNewLine(t1, t2 Token) bool {
	if t1.File != t2.File {
		return true
	}
	if len(t1.imports) != len(t2.imports) {
		return true
	}
	for i, im := range t1.imports {
		if im != t2.imports[i] {
			return true
		}
	}
	return t1.Line+fmtNumLineBreaks(t1) < t2.Line
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
	// lineStartsWithImport tracks whether the first token of the current
	// nesting-zero source line is "import". A standalone "{" that opens a
	// global-options block immediately after such a line must stay on its own
	// line instead of folding onto the import line (the "import" directive and a
	// global-options "{" are unrelated statements). See the import exception in
	// the isOpen case below.
	lineStartsWithImport := false

	for i := range tokens {
		if i == foldedOpenAt {
			// This "{" was already emitted ahead of a trailing comment.
			continue
		}
		tk := tokens[i]
		// Track whether the first token of the current nesting-zero source line
		// is "import". A token starts a new source line when it is the very
		// first token or is on a later line than its predecessor. This is
		// computed against the pre-token nesting so that a top-level "import"
		// line is recognized before any brace on a following line dedents.
		// Braces are not directives, so a line beginning with "{" or "}" leaves
		// the tracker untouched: the isOpen import exception below needs to see
		// the state established by the preceding import line.
		if !isCloseCurlyBrace(tk) && !isOpenCurlyBrace(tk) {
			startsNewLine := !wrote || fmtNextOnNewLine(tokens[i-1], tk)
			if startsNewLine {
				lineStartsWithImport = nesting == 0 && !tk.isComment && tk.Text == "import"
			}
		}
		isOpen := isOpenCurlyBrace(tk)
		// A structural close brace only closes a block when one is open. When
		// nesting is zero there is nothing to close (e.g. a "}" glued after a
		// backtick/quoted argument), so it is treated as an inline literal and
		// emitted verbatim at its source position.
		isClose := isCloseCurlyBrace(tk) && nesting > 0

		// A trailing comment shares its source line with the previous token
		// (e.g. after "}", after "{", or after a directive) and renders inline
		// on that line; a standalone comment sits alone on its own line.
		trailingComment := tk.isComment && wrote && !fmtNextOnNewLine(tokens[i-1], tk)

		// breaks is the number of newlines to emit before this token:
		//   0 = stay on the current line, 1 = new line, 2 = one blank line.
		breaks := 0
		if wrote {
			prev := tokens[i-1]
			if fmtNextOnNewLine(prev, tk) {
				breaks = 1
				// A gap of two or more lines yields at most one blank line.
				if tk.Line-(prev.Line+fmtNumLineBreaks(prev)) >= 2 {
					breaks = 2
				}
			}
		}

		switch {
		case isOpen:
			// An opening brace attaches to the current line: never break to a
			// new line before it (it joins the preceding token with a space).
			// EXCEPTION 1: a standalone comment line must keep the following "{"
			// on its own line, otherwise the "#" would comment the brace out.
			// EXCEPTION 2: a standalone "{" (one that begins a new source line)
			// that immediately follows a top-level "import" line, with no
			// intervening blank line, opens an unrelated global-options block
			// and must stay on its own line rather than folding onto the import.
			// If a blank line intervenes, it folds as usual and the blank is
			// dropped.
			standaloneBrace := wrote && fmtNextOnNewLine(tokens[i-1], tk)
			if prevWasComment {
				breaks = 1
			} else if lineStartsWithImport && nesting == 0 && standaloneBrace && breaks < 2 {
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
		// It only applies when the comment trails the block's head line (a
		// directive/address). If the comment trails an opening "{" (i.e. the
		// previous token is itself a "{"), the following "{" opens a separate
		// nested block on its own line and must NOT be folded up onto the comment
		// line; doing so is non-idempotent (a second pass sees the two "{" already
		// adjacent and breaks them apart again).
		if trailingComment && i+1 < len(tokens) && isOpenCurlyBrace(tokens[i+1]) && breaks == 0 && !atLineStart &&
			!isOpenCurlyBrace(tokens[i-1]) {
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
			// precededBySpace is only reliable after a quoted/backtick/heredoc
			// token (the delimiting space of an unquoted predecessor is consumed
			// by its own scan), so gluing an inline close brace is allowed only
			// when the previous token is quoted; otherwise the separator must be
			// preserved so two distinct tokens (e.g. "0" then "}") do not merge.
			inlineClose := isCloseCurlyBrace(tk) && !isClose && tokens[i-1].Quoted()
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
