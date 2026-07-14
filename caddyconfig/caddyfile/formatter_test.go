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
	"strconv"
	"strings"
	"testing"
)

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
	for i := 0; i < 12; i++ {
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
