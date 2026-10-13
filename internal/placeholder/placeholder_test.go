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

package placeholder

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestParseSingleAndString(t *testing.T) {
	for _, input := range []string{
		"{}", "{key}", `{a\:-b}`, "{a:-}", "{a:-{b:-c}}", `{a:-\{literal\}}`,
	} {
		ref, ok, err := ParseSingle(input)
		if err != nil || !ok || ref.String() != input {
			t.Fatalf("ParseSingle(%q) = (%+v, %v, %v), serialized %q", input, ref, ok, err, ref.String())
		}
	}
	for _, input := range []string{"", "literal", "{unclosed", "{key} trailing", "{a}{b}"} {
		if _, ok, err := ParseSingle(input); ok || err != nil {
			t.Fatalf("ParseSingle(%q) = (ok %v, error %v)", input, ok, err)
		}
	}
	if _, ok, err := ParseSingle("{a:-unclosed"); ok || err == nil {
		t.Fatalf("malformed default = (ok %v, error %v)", ok, err)
	}
}

func TestNamesAndWalk(t *testing.T) {
	input := `{"message":"{a\:-key:-prefix {b:-{c}} \{ignored\}}"} {d} \{escaped\}`
	want := []string{"a:-key", "b", "c", "d"}
	names, err := Names(input)
	if err != nil || !reflect.DeepEqual(names, want) {
		t.Fatalf("Names = %v, %v; want %v", names, err, want)
	}
	var visited []string
	marker := errors.New("stop walking")
	err = Walk(input, func(ref Reference) error {
		visited = append(visited, UnescapeKey(ref.Key))
		if ref.Key == "b" {
			return marker
		}
		return nil
	})
	if err != marker || !reflect.DeepEqual(visited, want[:2]) {
		t.Fatalf("Walk = %v, visited %v", err, visited)
	}
	if names, err := Names("{a} {b:-unclosed"); err == nil || names != nil {
		t.Fatalf("malformed discovery = %v, %v", names, err)
	}
	if _, err := Names(strings.Repeat("{a:-", MaxDepth+1) + "x" + strings.Repeat("}", MaxDepth+1)); err == nil {
		t.Fatal("discovery accepted excessive depth")
	}
}

func TestTraversalEscapeContexts(t *testing.T) {
	for _, tc := range []struct {
		input, want string
		names       []string
	}{
		{`\{a}`, `\{a}`, nil},
		{`\\{a}`, `\\{a}`, nil},
		{`{\{a}, \{b}}`, `{\{a}, \{b}}`, []string{`\{a`}},
		{`\{"value":"{a}"\}`, `\{"value":"{full.a}"\}`, []string{"a"}},
		{`{missing:-\{a\}}`, `{missing:-\{a\}}`, []string{"missing"}},
		{`{missing:-\\{a}}`, `{missing:-\\{full.a}}`, []string{"missing", "a"}},
	} {
		got, err := RewriteKeys(tc.input, func(key string) string {
			if key == "a" || key == "b" {
				return "full." + key
			}
			return key
		})
		if err != nil || got != tc.want {
			t.Errorf("RewriteKeys(%q) = %q, %v; want %q", tc.input, got, err, tc.want)
		}
		names, err := Names(tc.input)
		if err != nil || !reflect.DeepEqual(names, tc.names) {
			t.Errorf("Names(%q) = %v, %v; want %v", tc.input, names, err, tc.names)
		}
	}
}

func TestParse(t *testing.T) {
	for _, tc := range []struct {
		input string
		ref   Reference
		n     int
		err   bool
	}{
		{input: "plain"},
		{input: "{unclosed"},
		{input: "{key} suffix", ref: Reference{Key: "key"}, n: 5},
		{input: "{}", ref: Reference{}, n: 2},
		{input: "{:-empty-key}", ref: Reference{Key: ":-empty-key"}, n: 13},
		{input: "{a:b}", ref: Reference{Key: "a:b"}, n: 5},
		{input: `{a\:-b}`, ref: Reference{Key: `a\:-b`}, n: 7},
		{input: "{a:-b}", ref: Reference{Key: "a", Default: "b", HasDefault: true}, n: 6},
		{input: "{a:-}", ref: Reference{Key: "a", HasDefault: true}, n: 5},
		{input: "{a:-{b:-c}}tail", ref: Reference{Key: "a", Default: "{b:-c}", HasDefault: true}, n: 11},
		{input: `{a:-\{literal\}}`, ref: Reference{Key: "a", Default: `\{literal\}`, HasDefault: true}, n: 16},
		{input: `{a:-\\}tail`, ref: Reference{Key: "a", Default: `\\`, HasDefault: true}, n: 7},
		{input: `{a:-\}`, err: true},
		{input: "{a:-unclosed", err: true},
		{input: "{a:-{b}", err: true},
		{input: `{"key":"value:-x"}`, ref: Reference{Key: `"key":"value:-x"`}, n: 18},
		{input: `{{a:-b}}`, ref: Reference{Key: "{a:-b"}, n: 7},
		{input: `{a\}`, ref: Reference{Key: `a\`}, n: 4},
		{input: `{a\}tail}`, ref: Reference{Key: `a\}tail`}, n: 9},
	} {
		t.Run(tc.input, func(t *testing.T) {
			ref, n, err := Parse(tc.input)
			if (err != nil) != tc.err || ref != tc.ref || n != tc.n {
				t.Fatalf("Parse(%q) = (%+v, %d, %v); want (%+v, %d, error=%v)", tc.input, ref, n, err, tc.ref, tc.n, tc.err)
			}
		})
	}
}

func TestDepthLimit(t *testing.T) {
	valid := strings.Repeat("{a:-", MaxDepth) + "x" + strings.Repeat("}", MaxDepth)
	if _, n, err := Parse(valid); err != nil || n != len(valid) {
		t.Fatalf("maximum-depth expression rejected: %d, %v", n, err)
	}
	invalid := "{a:-" + valid + "}"
	if _, _, err := Parse(invalid); err == nil {
		t.Fatal("over-depth expression accepted")
	}
}

func TestRewriteKeys(t *testing.T) {
	input := `prefix {a:-hello {b:-{c}} \{literal\}} {d} \{escaped\}`
	want := `prefix {full.a:-hello {full.b:-{full.c}} \{literal\}} {full.d} \{escaped\}`
	actual, err := RewriteKeys(input, func(key string) string { return "full." + key })
	if err != nil || actual != want {
		t.Fatalf("got %q, %v; want %q", actual, err, want)
	}
}

func TestRewriteKeysInsideLegacyBraces(t *testing.T) {
	for _, input := range []string{
		`{"message":"{header.X:-fallback}"}`,
		`vars({'{header.X:-fallback}':['fallback']})`,
		strings.Repeat("{", 1000) + "{header.X:-fallback}",
	} {
		actual, err := RewriteKeys(input, func(key string) string {
			if key == "header.X" {
				return "http.request.header.X"
			}
			return key
		})
		want := strings.ReplaceAll(input, "header.X", "http.request.header.X")
		if err != nil || actual != want {
			t.Fatalf("got %q, %v; want %q", actual, err, want)
		}
	}
}

func TestRewriteTokens(t *testing.T) {
	input := `{a:-{b}} \{escaped\} {c}`
	var calls []string
	actual, err := RewriteTokens(input, func(token string) string {
		calls = append(calls, token)
		return "[" + token + "]"
	})
	want := `[{a:-{b}}] \{escaped\} [{c}]`
	if err != nil || actual != want || len(calls) != 2 || calls[0] != "{a:-{b}}" {
		t.Fatalf("got %q, %v, calls %v; want %q with two outer tokens", actual, err, calls, want)
	}
	for _, rewrite := range []func(string) (string, error){
		func(s string) (string, error) { return RewriteTokens(s, func(t string) string { return t }) },
		func(s string) (string, error) { return RewriteKeys(s, func(k string) string { return k }) },
	} {
		if _, err := rewrite("{a:-unclosed"); err == nil {
			t.Fatal("rewrite accepted malformed default")
		}
	}
}

func TestRewriteTokensInsideLegacyBraces(t *testing.T) {
	input := `vars({{key:-{other}}: ['fallback']})`
	var calls []string
	out, err := RewriteTokens(input, func(raw string) string {
		calls = append(calls, raw)
		return "DEFAULT"
	})
	if err != nil || out != `vars({DEFAULT: ['fallback']})` || len(calls) != 1 || calls[0] != `{key:-{other}}` {
		t.Fatalf("got %q, %v, calls %v", out, err, calls)
	}
}

func TestUnescapeKey(t *testing.T) {
	if got := UnescapeKey(`a\:-b\c\}d`); got != `a:-b\c\}d` {
		t.Fatalf("unexpected key: %q", got)
	}
}

func FuzzParse(f *testing.F) {
	for _, seed := range []string{"{a:-{b:-x}}", `{a:-\{literal\}}`, "{", `{"x":"y"}`, `\\{a}`, `{missing:-\\{a}}`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		ref, n, err := Parse(input)
		if n < 0 || n > len(input) || (err != nil && n != 0) {
			t.Fatalf("invalid result: n=%d err=%v input=%q", n, err, input)
		}
		if n > 0 && ref.String() != input[:n] {
			t.Fatalf("serialization changed reference %q to %q", input[:n], ref.String())
		}
		_, _ = Names(input)
		out, err := RewriteTokens(input, func(raw string) string { return raw })
		if err == nil && out != input {
			t.Fatalf("identity rewrite changed %q to %q", input, out)
		}
		out, err = RewriteKeys(input, func(key string) string { return key })
		if err == nil && out != input {
			t.Fatalf("identity key rewrite changed %q to %q", input, out)
		}
	})
}
