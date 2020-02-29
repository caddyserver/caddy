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
	"testing"
)

func TestFormatBasicIndentation(t *testing.T) {
	input := []byte(`
  a
b

	c {
		d
}

e { f
}
`)
	expected := []byte(`
a
b

c {
	d
}

e {
	f
}
`)
	testFormat(t, input, expected)
}

func TestFormatBasicSpacing(t *testing.T) {
	input := []byte(`
a{
	b
}

c{ d
}
`)
	expected := []byte(`
a {
	b
}

c {
	d
}
`)
	testFormat(t, input, expected)
}

func TestFormatEnvironmentVariable(t *testing.T) {
	input := []byte(`
{$A}

b {
{$C}
}

d { {$E}
}
`)
	expected := []byte(`
{$A}

b {
	{$C}
}

d {
	{$E}
}
`)
	testFormat(t, input, expected)
}

func TestFormatComments(t *testing.T) {
	input := []byte(`
# a "\n"

# b {
	c
}

d {
e # f
# g
}

h { # i
}
`)
	expected := []byte(`
# a "\n"

# b {
c
}

d {
	e # f
	# g
}

h {
	# i
}
`)
	testFormat(t, input, expected)
}

func TestFormatQuotesAndEscapes(t *testing.T) {
	input := []byte(`
"a \"b\" #c
	d

e {
"f"
}

g { "h"
}
`)
	expected := []byte(`
"a \"b\" #c
d

e {
	"f"
}

g {
	"h"
}
`)
	testFormat(t, input, expected)
}

func testFormat(t *testing.T, input, expected []byte) {
	output := Format(input)
	if string(output) != string(expected) {
		t.Errorf("Expected:\n%s\ngot:\n%s", string(output), string(expected))
	}
}
