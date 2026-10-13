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
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestReplacer(t *testing.T) {
	type testCase struct {
		input, expect, empty string
	}

	rep := testReplacer()

	// ReplaceAll
	for i, tc := range []testCase{
		{
			input:  "{",
			expect: "{",
		},
		{
			input:  `\{`,
			expect: `{`,
		},
		{
			input:  "foo{",
			expect: "foo{",
		},
		{
			input:  `foo\{`,
			expect: `foo{`,
		},
		{
			input:  "foo{bar",
			expect: "foo{bar",
		},
		{
			input:  `foo\{bar`,
			expect: `foo{bar`,
		},
		{
			input:  "foo{bar}",
			expect: "foo",
		},
		{
			input:  `foo\{bar\}`,
			expect: `foo{bar}`,
		},
		{
			input:  "}",
			expect: "}",
		},
		{
			input:  `\}`,
			expect: `}`,
		},
		{
			input:  "{}",
			expect: "",
		},
		{
			input:  `\{\}`,
			expect: `{}`,
		},
		{
			input:  `{"json": "object"}`,
			expect: "",
		},
		{
			input:  `\{"json": "object"}`,
			expect: `{"json": "object"}`,
		},
		{
			input:  `\{"json": "object"\}`,
			expect: `{"json": "object"}`,
		},
		{
			input:  `\{"json": "object{bar}"\}`,
			expect: `{"json": "object"}`,
		},
		{
			input:  `\{"json": \{"nested": "object"\}\}`,
			expect: `{"json": {"nested": "object"}}`,
		},
		{
			input:  `\{"json": \{"nested": "{bar}"\}\}`,
			expect: `{"json": {"nested": ""}}`,
		},
		{
			input:  `pre \{"json": \{"nested": "{bar}"\}\}`,
			expect: `pre {"json": {"nested": ""}}`,
		},
		{
			input:  `\{"json": \{"nested": "{bar}"\}\} post`,
			expect: `{"json": {"nested": ""}} post`,
		},
		{
			input:  `pre \{"json": \{"nested": "{bar}"\}\} post`,
			expect: `pre {"json": {"nested": ""}} post`,
		},
		{
			input:  `{{`,
			expect: "{{",
		},
		{
			input:  `{{}`,
			expect: "",
		},
		{
			input:  `{"json": "object"\}`,
			expect: "",
		},
		{
			input:  `{unknown}`,
			empty:  "-",
			expect: "-",
		},
		{
			input:  `back\slashes`,
			expect: `back\slashes`,
		},
		{
			input:  `double back\\slashes`,
			expect: `double back\\slashes`,
		},
		{
			input:  `placeholder {with \{ brace} in name`,
			expect: `placeholder  in name`,
		},
		{
			input:  `placeholder {with \} brace} in name`,
			expect: `placeholder  in name`,
		},
		{
			input:  `placeholder {with \} \} braces} in name`,
			expect: `placeholder  in name`,
		},
		{
			input:  `\{'group':'default','max_age':3600,'endpoints':[\{'url':'https://some.domain.local/a/d/g'\}],'include_subdomains':true\}`,
			expect: `{'group':'default','max_age':3600,'endpoints':[{'url':'https://some.domain.local/a/d/g'}],'include_subdomains':true}`,
		},
		{
			input:  `{}{}{}{\\\\}\\\\`,
			expect: `{\\\}\\\\`,
		},
		{
			input:  string([]byte{0x26, 0x00, 0x83, 0x7B, 0x84, 0x07, 0x5C, 0x7D, 0x84}),
			expect: string([]byte{0x26, 0x00, 0x83, 0x7B, 0x84, 0x07, 0x7D, 0x84}),
		},
		{
			input:  `\\}`,
			expect: `\}`,
		},
	} {
		actual := rep.ReplaceAll(tc.input, tc.empty)
		if actual != tc.expect {
			t.Errorf("Test %d: '%s': expected '%s' but got '%s'",
				i, tc.input, tc.expect, actual)
		}
	}
}

func TestReplacerSet(t *testing.T) {
	rep := testReplacer()

	for _, tc := range []struct {
		variable string
		value    any
	}{
		{
			variable: "test1",
			value:    "val1",
		},
		{
			variable: "asdf",
			value:    "123",
		},
		{
			variable: "numbers",
			value:    123.456,
		},
		{
			variable: "äöü",
			value:    "öö_äü",
		},
		{
			variable: "with space",
			value:    "space value",
		},
		{
			variable: "1",
			value:    "test-123",
		},
		{
			variable: "mySuper_IP",
			value:    "1.2.3.4",
		},
		{
			variable: "testEmpty",
			value:    "",
		},
	} {
		rep.Set(tc.variable, tc.value)

		// test if key is added
		if val, ok := rep.static[tc.variable]; ok {
			if val != tc.value {
				t.Errorf("Expected value '%s' for key '%s' got '%s'", tc.value, tc.variable, val)
			}
		} else {
			t.Errorf("Expected existing key '%s' found nothing", tc.variable)
		}
	}

	// test if all keys are still there (by length)
	length := len(rep.static)
	if len(rep.static) != 8 {
		t.Errorf("Expected length '%v' got '%v'", 7, length)
	}
}

func TestReplacerReplaceKnown(t *testing.T) {
	rep := Replacer{
		mapMutex: &sync.RWMutex{},
		providers: []replacementProvider{
			// split our possible vars to two functions (to test if both functions are called)
			ReplacerFunc(func(key string) (val any, ok bool) {
				switch key {
				case "test1":
					return "val1", true
				case "asdf":
					return "123", true
				case "äöü":
					return "öö_äü", true
				case "with space":
					return "space value", true
				default:
					return "NOOO", false
				}
			}),
			ReplacerFunc(func(key string) (val any, ok bool) {
				switch key {
				case "1":
					return "test-123", true
				case "mySuper_IP":
					return "1.2.3.4", true
				case "testEmpty":
					return "", true
				default:
					return "NOOO", false
				}
			}),
		},
	}

	for _, tc := range []struct {
		testInput string
		expected  string
	}{
		{
			// test vars without space
			testInput: "{test1}{asdf}{äöü}{1}{with space}{mySuper_IP}",
			expected:  "val1123öö_äütest-123space value1.2.3.4",
		},
		{
			// test vars with space
			testInput: "{test1} {asdf} {äöü} {1} {with space} {mySuper_IP} ",
			expected:  "val1 123 öö_äü test-123 space value 1.2.3.4 ",
		},
		{
			// test with empty val
			testInput: "{test1} {testEmpty} {asdf} {1} ",
			expected:  "val1 EMPTY 123 test-123 ",
		},
		{
			// test vars with not finished placeholders
			testInput: "{te{test1}{as{{df{1}",
			expected:  "{teval1{as{{dftest-123",
		},
		{
			// test with non existing vars
			testInput: "{test1} {nope} {1} ",
			expected:  "val1 {nope} test-123 ",
		},
	} {
		actual := rep.ReplaceKnown(tc.testInput, "EMPTY")

		// test if all are replaced as expected
		if actual != tc.expected {
			t.Errorf("Expected '%s' got '%s' for '%s'", tc.expected, actual, tc.testInput)
		}
	}
}

func TestReplacerDelete(t *testing.T) {
	rep := Replacer{
		mapMutex: &sync.RWMutex{},
		static: map[string]any{
			"key1": "val1",
			"key2": "val2",
			"key3": "val3",
			"key4": "val4",
		},
	}

	startLen := len(rep.static)

	toDel := []string{
		"key2", "key4",
	}

	for _, key := range toDel {
		rep.Delete(key)

		// test if key is removed from static map
		if _, ok := rep.static[key]; ok {
			t.Errorf("Expected '%s' to be removed. It is still in static map.", key)
		}
	}

	// check if static slice is smaller
	expected := startLen - len(toDel)
	actual := len(rep.static)
	if len(rep.static) != expected {
		t.Errorf("Expected length '%v' got length '%v'", expected, actual)
	}
}

func TestReplacerMap(t *testing.T) {
	rep := testReplacer()

	for i, tc := range []ReplacerFunc{
		func(key string) (val any, ok bool) {
			return "", false
		},
		func(key string) (val any, ok bool) {
			return "", false
		},
	} {
		rep.Map(tc)

		// test if function (which listens on specific key) is added by checking length
		if len(rep.providers) == i+1 {
			// check if the last function is the one we just added
			pTc := fmt.Sprintf("%p", tc)
			pRep := fmt.Sprintf("%p", rep.providers[i])
			if pRep != pTc {
				t.Errorf("Expected func pointer '%s' got '%s'", pTc, pRep)
			}
		} else {
			t.Errorf("Expected providers length '%v' got length '%v'", i+1, len(rep.providers))
		}
	}
}

func TestReplacerNew(t *testing.T) {
	repl := NewReplacer()

	if len(repl.providers) != 3 {
		t.Errorf("Expected providers length '%v' got length '%v'", 3, len(repl.providers))
	}

	// test if default global replacements are added as the first provider
	hostname, _ := os.Hostname()
	wd, _ := os.Getwd()
	os.Setenv("CADDY_REPLACER_TEST", "envtest")
	defer os.Setenv("CADDY_REPLACER_TEST", "")

	for _, tc := range []struct {
		variable string
		value    string
	}{
		{
			variable: "system.hostname",
			value:    hostname,
		},
		{
			variable: "system.slash",
			value:    string(filepath.Separator),
		},
		{
			variable: "system.os",
			value:    runtime.GOOS,
		},
		{
			variable: "system.arch",
			value:    runtime.GOARCH,
		},
		{
			variable: "system.wd",
			value:    wd,
		},
		{
			variable: "env.CADDY_REPLACER_TEST",
			value:    "envtest",
		},
	} {
		if val, ok := repl.providers[0].replace(tc.variable); ok {
			if val != tc.value {
				t.Errorf("Expected value '%s' for key '%s' got '%s'", tc.value, tc.variable, val)
			}
		} else {
			t.Errorf("Expected key '%s' to be recognized by first provider", tc.variable)
		}
	}

	// test if file provider is added as the second provider
	for _, tc := range []struct {
		variable string
		value    string
	}{
		{
			variable: "file.caddytest/integration/testdata/foo.txt",
			value:    "foo",
		},
		{
			variable: "file.caddytest/integration/testdata/foo_with_trailing_newline.txt",
			value:    "foo",
		},
		{
			variable: "file.caddytest/integration/testdata/foo_with_multiple_trailing_newlines.txt",
			value:    "foo" + getEOL(),
		},
	} {
		if val, ok := repl.providers[1].replace(tc.variable); ok {
			if val != tc.value {
				t.Errorf("Expected value '%s' for key '%s' got '%s'", tc.value, tc.variable, val)
			}
		} else {
			t.Errorf("Expected key '%s' to be recognized by second provider", tc.variable)
		}
	}
}

func getEOL() string {
	if os.PathSeparator == '\\' {
		return "\r\n" // Windows EOL
	}
	return "\n" // Unix and modern macOS EOL
}

func TestReplacerNewWithoutFile(t *testing.T) {
	repl := NewReplacer().WithoutFile()

	for _, tc := range []struct {
		variable string
		value    string
		notFound bool
	}{
		{
			variable: "file.caddytest/integration/testdata/foo.txt",
			notFound: true,
		},
		{
			variable: "system.os",
			value:    runtime.GOOS,
		},
	} {
		if val, ok := repl.Get(tc.variable); ok && !tc.notFound {
			if val != tc.value {
				t.Errorf("Expected value '%s' for key '%s' got '%s'", tc.value, tc.variable, val)
			}
		} else if !tc.notFound {
			t.Errorf("Expected key '%s' to be recognized", tc.variable)
		}
	}
}

func TestReplacerTimeNowRFC3339(t *testing.T) {
	originalNowFunc := nowFunc
	t.Cleanup(func() { nowFunc = originalNowFunc })

	for _, tc := range []struct {
		name string
		now  time.Time
		want string
	}{
		{
			name: "UTC",
			now:  time.Date(2026, time.October, 3, 4, 30, 0, 123456789, time.UTC),
			want: "2026-10-03T04:30:00Z",
		},
		{
			name: "numeric offset",
			now:  time.Date(2026, time.October, 3, 10, 15, 0, 123456789, time.FixedZone("NPT", 5*60*60+45*60)),
			want: "2026-10-03T10:15:00+05:45",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nowFunc = func() time.Time { return tc.now }
			got, ok := NewReplacer().GetString("time.now.rfc3339")
			if !ok {
				t.Fatal("time.now.rfc3339 placeholder was not found")
			}
			if got != tc.want {
				t.Fatalf("time.now.rfc3339 = %q; want %q", got, tc.want)
			}
		})
	}
}

func BenchmarkReplacer(b *testing.B) {
	type testCase struct {
		name, input, empty string
	}

	rep := testReplacer()
	rep.Set("str", "a string")
	rep.Set("int", 123.456)

	for _, bm := range []testCase{
		{
			name:  "no placeholder",
			input: `simple string`,
		},
		{
			name:  "string replacement",
			input: `str={str}`,
		},
		{
			name:  "int replacement",
			input: `int={int}`,
		},
		{
			name:  "placeholder",
			input: `{"json": "object"}`,
		},
		{
			name:  "escaped placeholder",
			input: `\{"json": \{"nested": "{bar}"\}\}`,
		},
	} {
		b.Run(bm.name, func(b *testing.B) {
			for b.Loop() {
				rep.ReplaceAll(bm.input, bm.empty)
			}
		})
	}
}

func testReplacer() Replacer {
	return Replacer{
		providers: make([]replacementProvider, 0),
		static:    make(map[string]any),
		mapMutex:  &sync.RWMutex{},
	}
}

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

// An empty error message does not make an error-valued provider missing.
type emptyPlaceholderError struct{}

func (*emptyPlaceholderError) Error() string { return "" }

func TestResolvePlaceholderKeepsEmptyErrors(t *testing.T) {
	r := NewEmptyReplacer()
	marker := new(emptyPlaceholderError)
	r.Set("error", marker)
	for _, expr := range []string{"{error:-success}", "{missing:-{error:-success}}", "{missing:-prefix {error:-success}}"} {
		value, found, err := r.ResolvePlaceholder(expr)
		if err != nil || !found || value != marker {
			t.Fatalf("%s=(%#v,%v,%v); want original typed error", expr, value, found, err)
		}
	}
}

func TestResolvePlaceholderContextOverrides(t *testing.T) {
	r := NewEmptyReplacer()
	r.Set("context", "regular")
	r.Set("primary", "present")
	var keys []string
	override := func(key string) (any, bool) {
		keys = append(keys, key)
		if key == "context" {
			return 42, true
		}
		return nil, false
	}
	value, found, err := r.ResolvePlaceholder("{missing:-{context}}", override)
	if err != nil || !found || value != 42 {
		t.Fatalf("override=(%#v,%v,%v)", value, found, err)
	}
	if !reflect.DeepEqual(keys, []string{"missing", "context"}) {
		t.Fatalf("lookups=%v", keys)
	}
	if original, _ := r.Get("context"); original != "regular" {
		t.Fatal("override mutated provider")
	}
	keys = nil
	value, _, err = r.ResolvePlaceholder("{primary:-{context}}", override)
	if err != nil || value != "present" || !reflect.DeepEqual(keys, []string{"primary"}) {
		t.Fatalf("unused branch evaluated: (%v,%v,%v)", value, keys, err)
	}
}

func TestReplacerReferenceAllocations(t *testing.T) {
	// AllocsPerRun measures process-wide allocations. Other tests can leave
	// background goroutines running, so measure in a fresh process which runs
	// only this test, retaining the race and coverage instrumentation.
	const childEnv = "CADDY_REPLACER_ALLOCATION_TEST_CHILD"
	if os.Getenv(childEnv) != "1" {
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(executable, "-test.run=^TestReplacerReferenceAllocations$", "-test.count=1", "-test.timeout=1m")
		cmd.Env = append(os.Environ(), childEnv+"=1")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("isolated allocation test failed: %v\n%s", err, output)
		}
		return
	}

	r := NewEmptyReplacer()
	r.Set("present", "value")
	for _, tc := range []struct {
		name  string
		build func(int) (input, want string)
	}{
		{"unknown", func(count int) (string, string) {
			input := strings.Repeat("{unknown}", count)
			return input, input
		}},
		{"nested unknown", func(count int) (string, string) {
			input := strings.Repeat("{", count) + "unknown}"
			return input, input
		}},
		{"selected default", func(count int) (string, string) {
			return strings.Repeat("{missing:-{present}}", count), strings.Repeat("value", count)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			small, _ := tc.build(10)
			large, want := tc.build(1000)
			if got := r.ReplaceKnown(large, ""); got != want {
				t.Fatalf("replacement = %q, want %q", got, want)
			}
			// Compare growth instead of an absolute count, which can vary
			// with the platform and instrumentation. Reconstructing every
			// unknown suffix or unused default would add hundreds of
			// allocations as the reference count grows from 10 to 1000.
			smallAllocs := testing.AllocsPerRun(100, func() { r.ReplaceKnown(small, "") })
			largeAllocs := testing.AllocsPerRun(100, func() { r.ReplaceKnown(large, "") })
			if largeAllocs > smallAllocs+8 {
				t.Fatalf("allocations grew from %.1f to %.1f for 10 versus 1000 references; want approximately constant", smallAllocs, largeAllocs)
			}
		})
	}
}

func BenchmarkReplacerScaling(b *testing.B) {
	r := NewEmptyReplacer()
	r.Set("present", "value")
	for _, count := range []int{100, 1000, 10000} {
		for _, tc := range []struct{ name, input string }{
			{"known", strings.Repeat("{present}", count)},
			{"unknown", strings.Repeat("{unknown}", count)},
			{"nested-unknown", strings.Repeat("{", count) + "unknown}"},
			{"unclosed", strings.Repeat("{", count)},
			{"defaults", strings.Repeat("{missing:-{present}}", count)},
			{"unclosed-default", "{missing:-" + strings.Repeat("x", count)},
		} {
			b.Run(fmt.Sprintf("%s/%d", tc.name, count), func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(tc.input)))
				for b.Loop() {
					r.ReplaceKnown(tc.input, "")
				}
			})
		}
	}
}
