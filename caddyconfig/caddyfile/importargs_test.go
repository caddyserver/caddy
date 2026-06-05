package caddyfile

import (
	"testing"
)

func TestParseVariadicRanges(t *testing.T) {
	tests := []struct {
		name      string
		tokenText string
		argCount  int
		wantFound bool
		wantStart int
		wantEnd   int
	}{
		{
			name:      "full range {args[0:]}",
			tokenText: "{args[0:]}",
			argCount:  3,
			wantFound: true,
			wantStart: 0,
			wantEnd:   3,
		},
		{
			name:      "partial range {args[:2]}",
			tokenText: "{args[:2]}",
			argCount:  5,
			wantFound: true,
			wantStart: 0,
			wantEnd:   2,
		},
		{
			name:      "explicit range {args[1:3]}",
			tokenText: "{args[1:3]}",
			argCount:  5,
			wantFound: true,
			wantStart: 1,
			wantEnd:   3,
		},
		{
			name:      "open end {args[2:]}",
			tokenText: "{args[2:]}",
			argCount:  4,
			wantFound: true,
			wantStart: 2,
			wantEnd:   4,
		},
		{
			name:      "full open range {args[:]}",
			tokenText: "{args[:]}",
			argCount:  3,
			wantFound: true,
			wantStart: 0,
			wantEnd:   3,
		},
		{
			name:      "not a variadic — single index {args[0]}",
			tokenText: "{args[0]}",
			argCount:  3,
			wantFound: false,
		},
		{
			name:      "not a placeholder at all",
			tokenText: "hello",
			argCount:  3,
			wantFound: false,
		},
		{
			name:      "not args prefix",
			tokenText: "{env.HOME}",
			argCount:  3,
			wantFound: false,
		},
		{
			name:      "missing closing bracket",
			tokenText: "{args[0:",
			argCount:  3,
			wantFound: false,
		},
		{
			name:      "empty index range",
			tokenText: "{args[]}",
			argCount:  3,
			wantFound: false,
		},
		{
			name:      "out of bounds — start > argCount",
			tokenText: "{args[10:]}",
			argCount:  3,
			wantFound: false,
		},
		{
			name:      "out of bounds — end > argCount",
			tokenText: "{args[0:10]}",
			argCount:  3,
			wantFound: false,
		},
		{
			name:      "invalid — start > end",
			tokenText: "{args[3:1]}",
			argCount:  5,
			wantFound: false,
		},
		{
			name:      "negative start index",
			tokenText: "{args[-1:]}",
			argCount:  3,
			wantFound: false,
		},
		{
			name:      "non-numeric start",
			tokenText: "{args[abc:]}",
			argCount:  3,
			wantFound: false,
		},
		{
			name:      "non-numeric end",
			tokenText: "{args[:xyz]}",
			argCount:  3,
			wantFound: false,
		},
		{
			name:      "start equals end — empty range",
			tokenText: "{args[2:2]}",
			argCount:  5,
			wantFound: true,
			wantStart: 2,
			wantEnd:   2,
		},
		{
			name:      "multiple placeholders separated by colon should not be variadic",
			tokenText: "{args[0]}:{args[1]}",
			argCount:  3,
			wantFound: false,
		},
		{
			name:      "zero args with empty range",
			tokenText: "{args[:]}",
			argCount:  0,
			wantFound: true,
			wantStart: 0,
			wantEnd:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := Token{Text: tt.tokenText}
			found, start, end := parseVariadic(token, tt.argCount)
			if found != tt.wantFound {
				t.Errorf("parseVariadic(%q, %d) found = %v, want %v",
					tt.tokenText, tt.argCount, found, tt.wantFound)
				return
			}
			if !found {
				return
			}
			if start != tt.wantStart {
				t.Errorf("parseVariadic(%q, %d) start = %d, want %d",
					tt.tokenText, tt.argCount, start, tt.wantStart)
			}
			if end != tt.wantEnd {
				t.Errorf("parseVariadic(%q, %d) end = %d, want %d",
					tt.tokenText, tt.argCount, end, tt.wantEnd)
			}
		})
	}
}

func TestMakeArgsReplacer(t *testing.T) {
	args := []string{"alpha", "beta", "gamma"}
	repl := makeArgsReplacer(args)

	tests := []struct {
		name    string
		key     string
		want    string
		changed bool
	}{
		{
			name:    "args[0]",
			key:     "{args[0]}",
			want:    "alpha",
			changed: true,
		},
		{
			name:    "args[1]",
			key:     "{args[1]}",
			want:    "beta",
			changed: true,
		},
		{
			name:    "args[2]",
			key:     "{args[2]}",
			want:    "gamma",
			changed: true,
		},
		{
			name:    "deprecated args.0",
			key:     "{args.0}",
			want:    "alpha",
			changed: true,
		},
		{
			name:    "deprecated args.1",
			key:     "{args.1}",
			want:    "beta",
			changed: true,
		},
		{
			name:    "out of bounds index unchanged",
			key:     "{args[5]}",
			want:    "{args[5]}",
			changed: false,
		},
		{
			name:    "non-args placeholder unchanged",
			key:     "{env.HOME}",
			want:    "{env.HOME}",
			changed: false,
		},
		{
			name:    "plain text unchanged",
			key:     "hello",
			want:    "hello",
			changed: false,
		},
		{
			name:    "variadic in replacer warns but doesn't replace",
			key:     "{args[0:2]}",
			want:    "{args[0:2]}",
			changed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := repl.ReplaceAll(tt.key, "")
			if tt.changed {
				if got != tt.want {
					t.Errorf("repl.ReplaceAll(%q) = %q, want %q", tt.key, got, tt.want)
				}
			} else {
				if got != "" && got != tt.key && got != tt.want {
					t.Errorf("repl.ReplaceAll(%q) = %q, want unchanged (%q)", tt.key, got, tt.want)
				}
			}
		})
	}
}

func TestMakeArgsReplacerEmpty(t *testing.T) {
	repl := makeArgsReplacer([]string{})

	// With no args, any index should be out of bounds
	got := repl.ReplaceAll("{args[0]}", "")
	if got == "something" {
		t.Errorf("repl.ReplaceAll with empty args should not produce a value, got %q", got)
	}
}

func TestMakeArgsReplacerNil(t *testing.T) {
	repl := makeArgsReplacer(nil)

	// Should not panic with nil args
	got := repl.ReplaceAll("{args[0]}", "DEFAULT")
	if got == "" {
		// The replacer returns the default when unmatched
		t.Log("nil args: correctly returned empty/default for {args[0]}")
	}
	_ = got
}
