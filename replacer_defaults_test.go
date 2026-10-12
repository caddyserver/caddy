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

package caddy

import (
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func TestReplacerDefaults(t *testing.T) {
	r := NewEmptyReplacer()
	r.Set("present", "value")
	r.Set("empty", "")
	r.Set("nil", nil)
	r.Set("false", false)
	r.Set("zero", 0)
	r.Set("colon:key", "colon value")
	r.Set("operator:-key", "operator value")
	r.Set("literal", "{env.SECRET}")
	r.Set("number", 42)

	for _, tc := range []struct {
		name, input, empty, want string
	}{
		{"present", "{present:-default}", "", "value"},
		{"missing", "{missing:-default}", "", "default"},
		{"empty", "{empty:-default}", "", "default"},
		{"nil", "{nil:-default}", "", "default"},
		{"false", "{false:-default}", "", "false"},
		{"zero", "{zero:-default}", "", "0"},
		{"empty default overrides sentinel", "before{missing:-}after", "sentinel", "beforeafter"},
		{"ordinary empty uses sentinel", "{empty}", "sentinel", "sentinel"},
		{"nested", "{missing:-{empty:-{present}}}", "", "value"},
		{"composite", "{missing:-prefix {present} suffix}", "", "prefix value suffix"},
		{"colon in fallback", "{missing:-https://example.com:8443/path}", "", "https://example.com:8443/path"},
		{"colon key", "{colon:key:-default}", "", "colon value"},
		{"legacy colon key", "{colon:key}", "", "colon value"},
		{"escaped operator key", `{operator\:-key:-default}`, "", "operator value"},
		{"provider text stays literal", "{missing:-{literal}}", "", "{env.SECRET}"},
		{"escaped fallback braces", `{missing:-\{literal\}}`, "", "{literal}"},
		{"escaped fallback slash", `{missing:-a\\b}`, "", `a\b`},
		{"multiple", "{missing:-one}/{empty:-two}/{number:-three}", "", "one/two/42"},
		{"negative JSON remains legacy", `{"x":-1}`, "", ""},
		{"plain JSON remains legacy", `{"x":1}`, "", ""},
		{"escaped JSON with default", `\{"x": "{missing:-ok}"\}`, "", `{"x": "ok"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := r.ReplaceAll(tc.input, tc.empty); got != tc.want {
				t.Fatalf("ReplaceAll(%q, %q) = %q; want %q", tc.input, tc.empty, got, tc.want)
			}
		})
	}

	if got, ok := r.Get("operator:-key"); !ok || got != "operator value" {
		t.Fatalf("Get must retain exact lookup: got (%v, %v)", got, ok)
	}
	if _, ok := r.Get("present:-default"); ok {
		t.Fatal("Get must not interpret default syntax")
	}
}

func TestResolvePlaceholderDefaults(t *testing.T) {
	r := NewEmptyReplacer()
	r.Set("number", 42)
	r.Set("false", false)
	r.Set("nil", nil)
	r.Set("literal", "{env.SECRET}")
	marker := fmt.Errorf("provider error")
	r.Set("error", marker)

	for _, tc := range []struct {
		input string
		want  any
		found bool
	}{
		{"{number}", 42, true},
		{"{number:-zero}", 42, true},
		{"{false:-true}", false, true},
		{"{nil}", nil, true},
		{"{nil:-default}", "default", true},
		{"{missing}", nil, false},
		{"{missing:-}", "", true},
		{"{missing:-{number}}", 42, true},
		{"{missing:-{false}}", false, true},
		{"{missing:-{missing}}", nil, false},
		{"{missing:-prefix {number}}", "prefix 42", true},
		{"{missing:-prefix {unknown}}", "prefix {unknown}", true},
		{"{missing:-{literal}}", "{env.SECRET}", true},
		{"{error:-default}", marker, true},
	} {
		t.Run(tc.input, func(t *testing.T) {
			got, found, err := r.ResolvePlaceholder(tc.input)
			if err != nil || found != tc.found || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("ResolvePlaceholder(%q) = (%#v, %v, %v); want (%#v, %v, nil)", tc.input, got, found, err, tc.want, tc.found)
			}
		})
	}
}

func TestReplacerDefaultsProviderEvaluation(t *testing.T) {
	r := NewEmptyReplacer()
	var keys []string
	r.Map(func(key string) (any, bool) {
		keys = append(keys, key)
		switch key {
		case "primary":
			return "present", true
		case "secondary":
			return "fallback", true
		default:
			return nil, false
		}
	})
	if got := r.ReplaceAll("{primary:-{secondary}}", ""); got != "present" {
		t.Fatalf("got %q", got)
	}
	if !reflect.DeepEqual(keys, []string{"primary"}) {
		t.Fatalf("provider calls = %v; unused fallbacks must not be evaluated", keys)
	}
	keys = nil
	if got := r.ReplaceAll("{missing:-{secondary}}", ""); got != "fallback" {
		t.Fatalf("got %q", got)
	}
	if !reflect.DeepEqual(keys, []string{"missing", "secondary"}) {
		t.Fatalf("provider calls = %v; default syntax must never be passed to providers", keys)
	}
}

func TestReplacerDefaultsReplacementFunc(t *testing.T) {
	r := NewEmptyReplacer()
	r.Set("primary", "")
	r.Set("secondary", "two words")
	r.Set("number", 42)

	for _, tc := range []struct {
		input, wantKey, want string
		wantValue            any
	}{
		{"{primary:-two words}", "", "two+words", "two words"},
		{"{primary:-{secondary}}", "secondary", "two+words", "two words"},
		{"{primary:-prefix {secondary}}", "", "prefix+two+words", "prefix two words"},
		{"{primary:-{number}}", "number", "42", 42},
	} {
		t.Run(tc.input, func(t *testing.T) {
			var calls int
			got, err := r.ReplaceFunc(tc.input, func(key string, value any) (any, error) {
				calls++
				if key != tc.wantKey || !reflect.DeepEqual(value, tc.wantValue) {
					t.Errorf("callback got (%q, %#v); want (%q, %#v)", key, value, tc.wantKey, tc.wantValue)
				}
				return url.QueryEscape(ToString(value)), nil
			})
			if err != nil || got != tc.want || calls != 1 {
				t.Fatalf("ReplaceFunc = (%q, %v), calls = %d; want (%q, nil), calls = 1", got, err, calls, tc.want)
			}
		})
	}
	marker := fmt.Errorf("callback error")
	if _, err := r.ReplaceFunc("{missing:-fallback}", func(string, any) (any, error) {
		return nil, marker
	}); err != marker {
		t.Fatalf("callback error = %v; want %v", err, marker)
	}
}

func TestReplacerDefaultsUnknownAndEmptyPolicies(t *testing.T) {
	r := NewEmptyReplacer()
	r.Set("empty", "")
	for _, tc := range []struct {
		input, want string
	}{
		{"{unknown}", "{unknown}"},
		{"{unknown:-literal}", "literal"},
		{"{unknown:-{other}}", "{other}"},
		{"{unknown:-prefix {other}}", "prefix {other}"},
	} {
		if got := r.ReplaceKnown(tc.input, ""); got != tc.want {
			t.Errorf("ReplaceKnown(%q) = %q; want %q", tc.input, got, tc.want)
		}
	}
	if got := r.ReplaceAll("{unknown:-prefix {other}}", ""); got != "prefix " {
		t.Errorf("ReplaceAll selected unknown fallback = %q; want %q", got, "prefix ")
	}
	if got, err := r.ReplaceOrErr("{unknown:-literal}", true, true); err != nil || got != "literal" {
		t.Errorf("resolved unknown primary = (%q, %v)", got, err)
	}
	for _, input := range []string{"{unknown:-}", "{empty:-}", "{unknown:-{other}}", "{unknown:-prefix {other}}"} {
		if _, err := r.ReplaceOrErr(input, true, true); err == nil {
			t.Errorf("ReplaceOrErr(%q, true, true) should fail", input)
		}
	}
}

func TestReplacerDefaultsNestingLimit(t *testing.T) {
	r := NewEmptyReplacer()
	input := strings.Repeat("{missing:-", 40) + "fallback" + strings.Repeat("}", 40)
	if _, _, err := r.ResolvePlaceholder(input); err == nil {
		t.Fatal("deep default nesting must return an error")
	}
	if _, err := r.ReplaceOrErr(input, false, false); err == nil {
		t.Fatal("replacement must reject deep default nesting")
	}
}

func BenchmarkReplacerDefaults(b *testing.B) {
	r := NewEmptyReplacer()
	r.Set("present", "value")
	for _, input := range []string{
		"plain text without placeholders",
		"{present}",
		"{present:-{unused}}",
		"{missing:-{other:-fallback}}",
	} {
		b.Run(input, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				r.ReplaceAll(input, "")
			}
		})
	}
}
