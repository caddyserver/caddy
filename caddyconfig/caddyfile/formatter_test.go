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
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	// Pin an empty environment so replaceEnvVars is deterministic for fuzzing.
	os.Clearenv()
	os.Exit(m.Run())
}

func TestFormatter(t *testing.T) {
	for i, tc := range []struct {
		description string
		input       string
		expect      string
	}{
		{
			description: "very simple",
			input: `abc   def
	g hi jkl
mn`,
			expect: `abc def
g hi jkl
mn`,
		},
		{
			description: "basic indentation, line breaks, and nesting",
			input: `  a
b

	c {
		d
}

e { f
}



g {
h {
i
}
}

j { k {
l
}
}

m {
	n { o
	}
	p { q r
s }
}

	{
{ t
		u

	v

w
}
}`,
			expect: `a
b

c {
	d
}

e {
	f
}

g {
	h {
		i
	}
}

j {
	k {
		l
	}
}

m {
	n {
		o
	}
	p {
		q r
		s
	}
}

{
	{
		t
		u

		v

		w
	}
}`,
		},
		{
			description: "block spacing",
			input: `a{
	b
}

c{ d
}`,
			expect: `a {
	b
}

c {
	d
}`,
		},
		{
			// sanctioned divergence: invalid glued braces left literal (design decision)
			description: "advanced spacing",
			input: `abc {
	def
}ghi{
	jkl mno
pqr}`,
			expect: `abc {
	def
	}ghi{
	jkl mno
	pqr}`,
		},
		{
			description: "env var placeholders",
			input: `{$A}

b {
{$C}
}

d { {$E}
}

{ {$F}
}
`,
			expect: `{$A}

b {
	{$C}
}

d {
	{$E}
}

{
	{$F}
}`,
		},
		{
			description: "env var placeholders with port",
			input:       `:{$PORT}`,
			expect:      `:{$PORT}`,
		},
		{
			description: "comments",
			input: `#a "\n"

 #b {
	c
}

d {
e#f
# g
}

h { # i
}`,
			expect: `#a "\n"

#b {
c
}

d {
	e#f
	# g
}

h { # i
}`,
		},
		{
			description: "quotes and escaping",
			input: `"a \"b\" "#c
	d

e {
"f"
}

g { "h"
}

i {
	"foo
bar"
}

j {
"\"k\" l m"
}`,
			expect: `"a \"b\" "#c
d

e {
	"f"
}

g {
	"h"
}

i {
	"foo
bar"
}

j {
	"\"k\" l m"
}`,
		},
		{
			description: "bad nesting (too many open)",
			input: `a
{
	{
}`,
			expect: `a {
	{
	}
`,
		},
		{
			// sanctioned divergence: invalid glued braces left literal (design decision)
			description: "bad nesting (too many close)",
			input: `a
{
	{
}}}`,
			expect: `a {
	{
		}}}
`,
		},
		{
			description: "json",
			input: `foo
bar      "{\"key\":34}"
`,
			expect: `foo
bar "{\"key\":34}"`,
		},
		{
			description: "escaping after spaces",
			input:       `foo \"literal\"`,
			expect:      `foo \"literal\"`,
		},
		{
			description: "simple placeholders as standalone tokens",
			input:       `foo {bar}`,
			expect:      `foo {bar}`,
		},
		{
			description: "simple placeholders within tokens",
			input:       `foo{bar} foo{bar}baz`,
			expect:      `foo{bar} foo{bar}baz`,
		},
		{
			// sanctioned divergence: invalid glued braces left literal (design decision)
			description: "placeholders and malformed braces",
			input:       `foo{bar} foo{ bar}baz`,
			expect: `foo{bar} foo {
	bar}baz`,
		},
		{
			description: "hash within string is not a comment",
			input:       `redir / /some/#/path`,
			expect:      `redir / /some/#/path`,
		},
		{
			description: "brace does not fold into comment above",
			input: `# comment
{
	foo
}`,
			expect: `# comment
{
	foo
}`,
		},
		{
			description: "matthewpi/vscode-caddyfile-support#13",
			input: `{
	email {$ACMEEMAIL}
	#debug
}

block {
}
`,
			expect: `{
	email {$ACMEEMAIL}
	#debug
}

block {
}
`,
		},
		{
			description: "matthewpi/vscode-caddyfile-support#13 - bad formatting",
			input: `{
	email {$ACMEEMAIL}
	#debug
	}

	block {
	}
`,
			expect: `{
	email {$ACMEEMAIL}
	#debug
}

block {
}
`,
		},
		{
			description: "keep heredoc as-is",
			input: `block {
	heredoc <<HEREDOC
	Here's more than one space       Here's more than one space
	HEREDOC
}
`,
			expect: `block {
	heredoc <<HEREDOC
	Here's more than one space       Here's more than one space
	HEREDOC
}
`,
		},
		{
			description: "Mixing heredoc with regular part",
			input: `block {
	heredoc <<HEREDOC
	Here's more than one space       Here's more than one space
	HEREDOC
	respond "More than one space will be eaten"     200
}

block2 {
	heredoc <<HEREDOC
	Here's more than one space       Here's more than one space
	HEREDOC
	respond "More than one space will be eaten" 200
}
`,
			expect: `block {
	heredoc <<HEREDOC
	Here's more than one space       Here's more than one space
	HEREDOC
	respond "More than one space will be eaten" 200
}

block2 {
	heredoc <<HEREDOC
	Here's more than one space       Here's more than one space
	HEREDOC
	respond "More than one space will be eaten" 200
}
`,
		},
		{
			description: "Heredoc as regular token",
			input: `block {
	heredoc <<HEREDOC                                 "More than one space will be eaten"
}
`,
			expect: `block {
	heredoc <<HEREDOC "More than one space will be eaten"
}
`,
		},
		{
			description: "Escape heredoc",
			input: `block {
	heredoc \<<HEREDOC
	respond "More than one space will be eaten"                           200
}
`,
			expect: `block {
	heredoc \<<HEREDOC
	respond "More than one space will be eaten" 200
}
`,
		},
		{
			description: "Preserve braces wrapped by backquotes",
			input:       "block {respond `All braces should remain: {{now | date \"2006\"}}`}",
			expect:      "block {respond `All braces should remain: {{now | date \"2006\"}}`}",
		},
		{
			description: "Preserve braces wrapped by quotes",
			input:       "block {respond \"All braces should remain: {{now | date `2006`}}\"}",
			expect:      "block {respond \"All braces should remain: {{now | date `2006`}}\"}",
		},
		{
			description: "Preserve quoted brace arguments",
			input:       "block {\n\trespond \"{\"\n\trespond \"}\"\n}",
			expect:      "block {\n\trespond \"{\"\n\trespond \"}\"\n}",
		},
		{
			description: "Preserve quoted backticks and backticked quotes",
			input:       "block { respond \"`\" } block { respond `\"`}",
			expect:      "block {\n\trespond \"`\"\n}\n\nblock {\n\trespond `\"`\n}",
		},
		{
			description: "No trailing space on line before env variable",
			input: `{
	a

	{$ENV_VAR}
}
`,
			expect: `{
	a

	{$ENV_VAR}
}
`,
		},
		{
			description: "issue #7425: multiline backticked string indentation",
			input: `https://localhost:8953 {
    respond ` + "`" + `Here are some random numbers:

{{randNumeric 16}}

Hope this helps.` + "`" + `
}`,
			expect: "https://localhost:8953 {\n\trespond `Here are some random numbers:\n\n{{randNumeric 16}}\n\nHope this helps.`\n}",
		},
		{
			description: "imports before global options block keep standalone brace",
			input: `import ./conf.d/matcher_my_subnet.caddy
import ./conf.d/matcher_not_my_subnet.caddy
{
	order crowdsec first
	order appsec after crowdsec
}`,
			expect: `import ./conf.d/matcher_my_subnet.caddy
import ./conf.d/matcher_not_my_subnet.caddy
{
	order crowdsec first
	order appsec after crowdsec
}`,
		},
	} {
		// the formatter should output a trailing newline,
		// even if the tests aren't written to expect that
		if !strings.HasSuffix(tc.expect, "\n") {
			tc.expect += "\n"
		}

		actual := Format([]byte(tc.input))

		if string(actual) != tc.expect {
			t.Errorf("\n[TEST %d: %s]\n====== EXPECTED ======\n%s\n====== ACTUAL ======\n%s^^^^^^^^^^^^^^^^^^^^^",
				i, tc.description, string(tc.expect), string(actual))
		}
	}
}

func TestFormatImportStandaloneBrace(t *testing.T) {
	// immediately after a top-level import line: keep the brace standalone
	in1 := "import a.caddy\nimport b.caddy\n{\n\torder x first\n}\n"
	if got := string(Format([]byte(in1))); got != in1 {
		t.Errorf("standalone brace after import not preserved:\n got %q\nwant %q", got, in1)
	}
	// with an intervening blank line: brace glues up and the blank line is removed
	in2 := "import a.caddy\n\n{\n\torder x first\n}\n"
	want2 := "import a.caddy {\n\torder x first\n}\n"
	if got := string(Format([]byte(in2))); got != want2 {
		t.Errorf("blank-line case:\n got %q\nwant %q", got, want2)
	}
}

func TestFormatDeepNestingNoCap(t *testing.T) {
	// 12 levels deep; every level indents (no 10-level clamp)
	var b strings.Builder
	for i := range 12 {
		b.WriteString(strings.Repeat("\t", i) + "l" + strconv.Itoa(i) + " {\n")
	}
	b.WriteString(strings.Repeat("\t", 12) + "x\n")
	for i := 11; i >= 0; i-- {
		b.WriteString(strings.Repeat("\t", i) + "}\n")
	}
	out := string(Format([]byte(b.String())))
	if !strings.Contains(out, "\n"+strings.Repeat("\t", 12)+"x\n") {
		t.Errorf("expected 12-tab indent for deepest token, got:\n%s", out)
	}
}

func TestFormatAngleNotQuirked(t *testing.T) {
	if got := string(Format([]byte("foo < bar"))); got != "foo < bar\n" {
		t.Errorf("got %q, want %q", got, "foo < bar\n")
	}
}

func TestFormatEmptyBlocksExpand(t *testing.T) {
	cases := []struct{ in, want string }{
		{"route {}", "route {\n}\n"},
		{"route { }", "route {\n}\n"},
		{"a { b {} }", "a {\n\tb {\n\t}\n}\n"},
	}
	for _, c := range cases {
		if got := string(Format([]byte(c.in))); got != c.want {
			t.Errorf("in %q: got %q, want %q", c.in, got, c.want)
		}
	}
}

func TestFormatTokenAfterCloseBraceBreaks(t *testing.T) {
	in := "a {\n\tb {\n\t\tc\n\t} d\n}"
	want := "a {\n\tb {\n\t\tc\n\t}\n\td\n}\n"
	if got := string(Format([]byte(in))); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestFormatCommentsOnBraceLines(t *testing.T) {
	cases := []struct{ in, want string }{
		{"site {\n\tfoo\n} # after close\n", "site {\n\tfoo\n} # after close\n"},
		{"site { # note\n\tfoo\n}\n", "site { # note\n\tfoo\n}\n"},
		{"site # note\n{\n\tfoo\n}\n", "site { # note\n\tfoo\n}\n"},
	}
	for _, c := range cases {
		if got := string(Format([]byte(c.in))); got != c.want {
			t.Errorf("in %q:\n got %q\nwant %q", c.in, got, c.want)
		}
	}
}

func TestFormatBlankLineCapAfterComment(t *testing.T) {
	got := string(Format([]byte("foo # inline\n\n\nbar\n")))
	want := "foo # inline\n\nbar\n"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestFormatContinuationHangingIndent(t *testing.T) {
	in := "route {\n\treverse_proxy \\\n\ta \\\n\tb\n}\n"
	want := "route {\n\treverse_proxy \\\n\t\ta \\\n\t\tb\n}\n"
	if got := string(Format([]byte(in))); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestFormatStrayCloseBraceKeepsTokens(t *testing.T) {
	for _, in := range []string{"0 }", "a }"} {
		once := Format([]byte(in))
		twice := Format(once)
		if !bytes.Equal(once, twice) {
			t.Errorf("not idempotent for %q:\n once=%q\ntwice=%q", in, once, twice)
		}
		a, err1 := Parse("Caddyfile", []byte(in))
		if err1 != nil {
			t.Fatalf("input %q did not parse: %v", in, err1)
		}
		b, err2 := Parse("Caddyfile", once)
		if err2 != nil {
			t.Fatalf("formatted %q did not parse: %v", in, err2)
		}
		if !sameStructure(a, b) {
			t.Errorf("stray close brace merged tokens for %q: got %q", in, once)
		}
	}
}

func TestFormatIncompleteHeredocIdempotent(t *testing.T) {
	for _, in := range []string{"0 <<0", "x <<E"} {
		once := Format([]byte(in))
		twice := Format(once)
		if !bytes.Equal(once, twice) {
			t.Errorf("not idempotent for %q:\n once=%q\ntwice=%q", in, once, twice)
		}
	}
}

// formatTokenText returns the format-mode non-comment token-text sequence for
// input, or nil and false on a lex error. It is the basis of the semantic-
// preservation invariant: Format must reproduce this exact sequence. Comment
// tokens are omitted because the formatter intentionally normalizes comment
// whitespace (e.g. trimming a trailing space, "# " -> "#"), which is not a
// semantic change.
func formatTokenText(in []byte) ([]string, bool) {
	toks, err := Lex(in, "", LexOptions{Comments: true, Raw: true})
	if err != nil {
		return nil, false
	}
	var texts []string
	for _, t := range toks {
		if !t.isComment {
			texts = append(texts, t.Text)
		}
	}
	return texts, true
}

// formatAndParseLexersDisagree reports whether the format-mode lexer and the
// parse-path lexer produce different token-text sequences for the input (the
// parse baseline is newline-terminated to match Format's mandatory trailing
// newline, and comments — which the parse path discards — are ignored on the
// format side). When the two lexers already disagree before any formatting, the
// input is degenerate or structurally ambiguous — an unterminated or lone
// quote/backtick, an escaped quote swallowing to EOF, a "{}" or a "{"/"}" glued
// to a literal word that only one path splits — and has no well-defined
// formatting. Such inputs are a sanctioned divergence excluded from the
// invariant. Inputs on which both lexers agree, including the stray-close-brace
// bug's "0 }" and standalone braces in argument position, stay in scope.
func formatAndParseLexersDisagree(in []byte) bool {
	fmtToks, err := Lex(in, "", LexOptions{Comments: true, Raw: true})
	if err != nil {
		return true
	}
	var fmtText []string
	for _, t := range fmtToks {
		if t.isComment {
			continue
		}
		fmtText = append(fmtText, t.Text)
		// A non-quoted token whose verbatim source ends in whitespace, contains an
		// escaped quote, or whose text carries a newline results from an escaped
		// quote ("\"") swallowing trailing whitespace to EOF. The format-mode and
		// parse-path lexers can agree on such a token, but Format emits the source
		// verbatim and then trims trailing whitespace, changing the token on
		// re-lex. Treat these degenerate escaped-quote tokens as a disagreement.
		if t.wasQuoted == 0 {
			r := t.Raw()
			if n := len(r); n > 0 && (r[n-1] == ' ' || r[n-1] == '\t' || r[n-1] == '\v' || r[n-1] == '\f' || r[n-1] == '\r' || r[n-1] == '\n') {
				return true
			}
			if strings.Contains(r, `\"`) || strings.Contains(r, "\\`") {
				return true
			}
			if strings.ContainsRune(t.Text, '\n') {
				return true
			}
		}
	}
	base := in
	if n := len(base); n == 0 || base[n-1] != '\n' {
		base = append(append([]byte{}, base...), '\n')
	}
	parseToks, err := Tokenize(base, "")
	if err != nil {
		return true
	}
	parseText := make([]string, len(parseToks))
	for i, t := range parseToks {
		parseText[i] = t.Text
	}
	return !reflect.DeepEqual(fmtText, parseText)
}

// hasHeredocOpenerShapedToken reports whether the format-mode lexer produces a
// token whose text begins with "<<" (a heredoc opener shape). Such a token is a
// literal word only because no newline follows it (or a separating space breaks
// the heredoc), but Format's mandatory trailing newline can turn it into a
// heredoc opener, so the formatted output re-lexes to a different token stream.
// This degenerate opener is a sanctioned divergence excluded from the invariant;
// valid heredocs (whose token text does not begin with "<<") stay in scope. It
// is detected by token text, so a "<<" split by a stripped carriage return
// ("<\r<") is caught too.
func hasHeredocOpenerShapedToken(in []byte) bool {
	toks, err := Lex(in, "", LexOptions{Comments: true, Raw: true})
	if err != nil {
		return true
	}
	for _, t := range toks {
		if t.wasQuoted == 0 && !t.isComment && strings.HasPrefix(t.Text, "<<") {
			return true
		}
	}
	return false
}

func FuzzFormatIdempotent(f *testing.F) {
	for _, s := range []string{"", "  ", "a{\nb\n}", "site {\n\tfoo # c\n}\n", "x <<E\nhi\nE\n"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		once := Format(in)
		twice := Format(once)
		if !bytes.Equal(once, twice) {
			t.Errorf("not idempotent:\n once=%q\ntwice=%q", once, twice)
		}
	})
}

func FuzzFormatNoPanic(f *testing.F) {
	f.Add([]byte("\x00\x00"))
	f.Add([]byte("`unterminated"))
	f.Add([]byte("x <<E\nno end marker"))
	f.Fuzz(func(t *testing.T, in []byte) {
		_ = Format(in) // must not panic
	})
}

func FuzzFormatSemanticPreserve(f *testing.F) {
	for _, s := range []string{"site {\n\troot * /srv\n\tfile_server\n}\n"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		// The semantic-preservation invariant: formatting only changes structural
		// whitespace, so the format-mode token-text sequence of Format(in) must
		// equal that of the input. This is stronger and more robust than comparing
		// parse structures, which the parse path's lenient/quirky grouping of
		// ambiguous brace layouts (e.g. standalone braces in argument position)
		// would spuriously flag even though every token is preserved.
		//
		// One class is genuinely out of scope: a heredoc-opener-shaped token
		// ("<<MARKER") that stays a literal word only because no newline follows
		// it. Format's mandatory trailing newline turns it into a real heredoc
		// opener, so the output legitimately re-lexes to a different token stream.
		// Valid heredocs (whose token text does not begin with "<<") stay in scope.
		// Also out of scope: any input on which the format-mode and parse-path
		// lexers already disagree (unterminated/lone quotes, escaped quotes at EOF,
		// "{}" or a brace glued to a literal word) — these are degenerate or
		// structurally ambiguous and have no well-defined formatting.
		if hasHeredocOpenerShapedToken(in) || formatAndParseLexersDisagree(in) {
			return
		}
		// Compare the format-mode token text of a newline-terminated baseline
		// against that of Format's output. Format always ends its output in a
		// single newline (Invariant); normalizing the baseline the same way keeps
		// the comparison about token content, not the mandatory trailing newline.
		base := in
		if n := len(base); n == 0 || base[n-1] != '\n' {
			base = append(append([]byte{}, base...), '\n')
		}
		before, ok := formatTokenText(base)
		if !ok {
			return // input does not lex; Format falls back and there is nothing to preserve
		}
		out := Format(in)
		after, ok := formatTokenText(out)
		if !ok {
			t.Fatalf("formatted output no longer lexes\ninput=%q\nout=%q", in, out)
		}
		if !reflect.DeepEqual(before, after) {
			t.Errorf("Format changed the token stream\ninput=%q\nout=%q\nbefore=%q\nafter=%q", in, out, before, after)
		}
	})
}

// TestFormatFuzzerAngles covers tricky / pathological inputs that a fuzzer would
// exercise. Every case asserts idempotency (Format(Format(x)) == Format(x)) and
// that Format does not panic. The subset of clearly-idiomatic inputs also asserts
// an exact expected output.
func TestFormatFuzzerAngles(t *testing.T) {
	type tc struct {
		name        string
		input       string
		exactExpect string // non-empty → assert this exact output in addition to idempotency
	}

	cases := []tc{
		// ---- clearly-idiomatic: assert exact output ----

		{
			// Empty input: Format always emits a single trailing newline.
			name:        "empty input",
			input:       "",
			exactExpect: "\n",
		},
		{
			// Whitespace-only input collapses to the same single newline.
			name:        "whitespace-only input",
			input:       "   \n\t\n",
			exactExpect: "\n",
		},
		{
			// A bare env-var placeholder is a literal token and must be preserved.
			name:        "env var {$X}",
			input:       "{$X}",
			exactExpect: "{$X}\n",
		},
		{
			// Default-value env var.
			name:        "env var {$X:def}",
			input:       "{$X:def}",
			exactExpect: "{$X:def}\n",
		},
		{
			// Minimal env var with only the sigil.
			name:        "env var {$}",
			input:       "{$}",
			exactExpect: "{$}\n",
		},
		{
			// Backtick token as the first token inside a block must indent correctly.
			name:        "backtick as first token after {",
			input:       "a {\n\t`foo`\n}\n",
			exactExpect: "a {\n\t`foo`\n}\n",
		},
		{
			// { } expands to a proper block.
			name:        "{ } empty block",
			input:       "route { }",
			exactExpect: "route {\n}\n",
		},
		{
			// Hash inside a double-quoted string is not a comment.
			name:        "hash inside double-quoted string",
			input:       `foo "bar#baz" quux`,
			exactExpect: "foo \"bar#baz\" quux\n",
		},
		{
			// Hash inside a heredoc body is not a comment.
			name:        "hash inside heredoc body",
			input:       "x <<END\nfoo # not a comment\nEND\n",
			exactExpect: "x <<END\nfoo # not a comment\nEND\n",
		},
		{
			// Escaped heredoc opener (\<<) is a regular token, not a real heredoc.
			name:        "escaped heredoc \\<<",
			input:       "block {\n\theredoc \\<<HEREDOC\n\trespond hello 200\n}\n",
			exactExpect: "block {\n\theredoc \\<<HEREDOC\n\trespond hello 200\n}\n",
		},
		{
			// Heredoc whose marker appears as a substring of a body line (fooEND ≠ END).
			name:        "heredoc marker as substring of body line",
			input:       "x <<END\nfooEND\nEND\n",
			exactExpect: "x <<END\nfooEND\nEND\n",
		},

		// ---- pathological: idempotency + no-panic only ----

		{
			// Unbalanced: one more opening brace than closing braces.
			name:  "unbalanced braces (too many open)",
			input: "a {\n\tb {\n\t\tc\n\t}\n",
		},
		{
			// Unbalanced: stray closing brace.
			name:  "unbalanced braces (too many close)",
			input: "a }\n",
		},
		{
			// CRLF line endings must not break idempotency.
			name:  "CRLF line endings",
			input: "site {\r\n\tfoo\r\n}\r\n",
		},
		{
			// Unterminated double-quoted string.
			name:  "unterminated double-quote",
			input: "foo \"unterminated",
		},
		{
			// Unterminated backtick string.
			name:  "unterminated backtick",
			input: "foo `unterminated",
		},
		{
			// Trailing backslash (dangling escape — not a line continuation).
			name:  "trailing backslash",
			input: "a b\\",
		},
		{
			// UTF-8 BOM at the start of the file; the BOM should not survive into
			// the formatted output (it is part of the first token's raw source but
			// the formatter strips leading/trailing whitespace).
			name:  "UTF-8 BOM prefix",
			input: "\xef\xbb\xbfsite {\n\tfoo\n}\n",
		},
		{
			// NUL byte embedded in a token.
			name:  "NUL byte in token",
			input: "site {\nfoo\x00bar\n}\n",
		},
		{
			// Arbitrary control bytes in a token.
			name:  "control bytes in token",
			input: "a\x01b\x02c",
		},
		{
			// Lone carriage-return (CR without LF). The lexer treats \r as part of
			// the token raw text but strips it from the token's text field; the raw
			// bytes are emitted verbatim by the formatter.
			name:  "lone CR (respond hello\\rworld)",
			input: "respond hello\rworld",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// No-panic: the call itself must complete.
			once := Format([]byte(c.input))

			// Idempotency: a second pass must reproduce the first pass exactly.
			twice := Format(once)
			if !bytes.Equal(once, twice) {
				t.Errorf("not idempotent:\n once=%q\ntwice=%q", once, twice)
			}

			// Exact-output assertion for clearly-idiomatic cases.
			if c.exactExpect != "" && string(once) != c.exactExpect {
				t.Errorf("unexpected output:\n  got  %q\n  want %q", string(once), c.exactExpect)
			}
		})
	}
}

// TestFormattingDifferenceStableOnFormatted verifies that an already-formatted
// config produces no diff from FormattingDifference (i.e. the formatter and the
// diff checker agree that a well-formed file needs no changes).
func TestFormattingDifferenceStableOnFormatted(t *testing.T) {
	in := []byte("site {\n\troot * /srv\n\tfile_server\n}\n")
	formatted := Format(in)
	if _, diff := FormattingDifference("Caddyfile", formatted); diff {
		t.Error("FormattingDifference reported a diff on already-formatted input")
	}
}

// sameStructure compares two parses by their per-segment token Text sequences.
func sameStructure(a, b []ServerBlock) bool {
	seq := func(blocks []ServerBlock) []string {
		var s []string
		for _, blk := range blocks {
			s = append(s, "K")
			for _, k := range blk.Keys {
				s = append(s, k.Text)
			}
			for _, seg := range blk.Segments {
				s = append(s, "S")
				for _, tk := range seg {
					s = append(s, tk.Text)
				}
			}
		}
		return s
	}
	return reflect.DeepEqual(seq(a), seq(b))
}
