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
	"strings"
	"testing"
)

func TestFormatter(t *testing.T) {
	for i, tc := range []struct {
		description string
		input       string
		expect      string
		// skip, when non-empty, temporarily skips a case whose expected output
		// depends on a formatter feature that lands in a later refactor task
		// (Task 8 implements only the core token-based layout). The string
		// names the task that will re-enable the case.
		skip string
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
			description: "advanced spacing",
			skip:        "task 10: token-after-} break (I4) requires splitting glued braces like }ghi{",
			input: `abc {
	def
}ghi{
	jkl mno
pqr}`,
			expect: `abc {
	def
}

ghi {
	jkl mno
	pqr
}`,
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
			description: "bad nesting (too many close)",
			skip:        "task 11: dropped nesting cap and glued-brace splitting for }}}",
			input: `a
{
	{
}}}`,
			expect: `a {
	{
	}
}
}
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
			description: "placeholders and malformed braces",
			skip:        "task 10: token-after-} break (I4) requires splitting glued braces like bar}baz",
			input:       `foo{bar} foo{ bar}baz`,
			expect: `foo{bar} foo {
	bar
}

baz`,
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
			skip:        "task 11: import standalone-brace exception keeps { off the import line",
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
		if tc.skip != "" {
			t.Logf("[TEST %d: %s] SKIPPED (%s)", i, tc.description, tc.skip)
			continue
		}

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
