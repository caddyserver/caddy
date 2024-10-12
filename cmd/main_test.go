package caddycmd

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseEnvFile(t *testing.T) {
	for i, tc := range []struct {
		input     string
		expect    map[string]string
		shouldErr bool
	}{
		{
			input: `KEY=value`,
			expect: map[string]string{
				"KEY": "value",
			},
		},
		{
			input: `
				KEY=value
				OTHER_KEY=Some Value
			`,
			expect: map[string]string{
				"KEY":       "value",
				"OTHER_KEY": "Some Value",
			},
		},
		{
			input: `
				KEY=value
				INVALID KEY=asdf
				OTHER_KEY=Some Value
			`,
			shouldErr: true,
		},
		{
			input: `
				KEY=value
				SIMPLE_QUOTED="quoted value"
				OTHER_KEY=Some Value
			`,
			expect: map[string]string{
				"KEY":           "value",
				"SIMPLE_QUOTED": "quoted value",
				"OTHER_KEY":     "Some Value",
			},
		},
		{
			input: `
				KEY=value
				NEWLINES="foo
	bar"
				OTHER_KEY=Some Value
			`,
			expect: map[string]string{
				"KEY":       "value",
				"NEWLINES":  "foo\n\tbar",
				"OTHER_KEY": "Some Value",
			},
		},
		{
			input: `
				KEY=value
				ESCAPED="\"escaped quotes\"
here"
				OTHER_KEY=Some Value
			`,
			expect: map[string]string{
				"KEY":       "value",
				"ESCAPED":   "\"escaped quotes\"\nhere",
				"OTHER_KEY": "Some Value",
			},
		},
		{
			input: `
				export KEY=value
				OTHER_KEY=Some Value
			`,
			expect: map[string]string{
				"KEY":       "value",
				"OTHER_KEY": "Some Value",
			},
		},
		{
			input: `
				=value
				OTHER_KEY=Some Value
			`,
			shouldErr: true,
		},
		{
			input: `
				EMPTY=
				OTHER_KEY=Some Value
			`,
			expect: map[string]string{
				"EMPTY":     "",
				"OTHER_KEY": "Some Value",
			},
		},
		{
			input: `
				EMPTY=""
				OTHER_KEY=Some Value
			`,
			expect: map[string]string{
				"EMPTY":     "",
				"OTHER_KEY": "Some Value",
			},
		},
		{
			input: `
				KEY=value
				#OTHER_KEY=Some Value
			`,
			expect: map[string]string{
				"KEY": "value",
			},
		},
		{
			input: `
				KEY=value
				COMMENT=foo bar  # some comment here
				OTHER_KEY=Some Value
			`,
			expect: map[string]string{
				"KEY":       "value",
				"COMMENT":   "foo bar",
				"OTHER_KEY": "Some Value",
			},
		},
		{
			input: `
				KEY=value
				WHITESPACE=   foo 
				OTHER_KEY=Some Value
			`,
			shouldErr: true,
		},
		{
			input: `
				KEY=value
				WHITESPACE="   foo bar "
				OTHER_KEY=Some Value
			`,
			expect: map[string]string{
				"KEY":        "value",
				"WHITESPACE": "   foo bar ",
				"OTHER_KEY":  "Some Value",
			},
		},
	} {
		actual, err := parseEnvFile(strings.NewReader(tc.input))
		if err != nil && !tc.shouldErr {
			t.Errorf("Test %d: Got error but shouldn't have: %v", i, err)
		}
		if err == nil && tc.shouldErr {
			t.Errorf("Test %d: Did not get error but should have", i)
		}
		if tc.shouldErr {
			continue
		}
		if !reflect.DeepEqual(tc.expect, actual) {
			t.Errorf("Test %d: Expected %v but got %v", i, tc.expect, actual)
		}
	}
}

func Test_isCaddyfile(t *testing.T) {
	type args struct {
		configFile  string
		adapterName string
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		{
			name: "bare Caddyfile without adapter",
			args: args{
				configFile:  "Caddyfile",
				adapterName: "",
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "local Caddyfile without adapter",
			args: args{
				configFile:  "./Caddyfile",
				adapterName: "",
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "local caddyfile with adapter",
			args: args{
				configFile:  "./Caddyfile",
				adapterName: "caddyfile",
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ends with .caddyfile with adapter",
			args: args{
				configFile:  "./conf.caddyfile",
				adapterName: "caddyfile",
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ends with .caddyfile without adapter",
			args: args{
				configFile:  "./conf.caddyfile",
				adapterName: "",
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "config is Caddyfile.yaml with adapter",
			args: args{
				configFile:  "./Caddyfile.yaml",
				adapterName: "yaml",
			},
			want:    false,
			wantErr: false,
		},
		{

			name: "json is not caddyfile but not error",
			args: args{
				configFile:  "./Caddyfile.json",
				adapterName: "",
			},
			want:    false,
			wantErr: false,
		},
		{

			name: "prefix of Caddyfile and ./ with any extension is Caddyfile",
			args: args{
				configFile:  "./Caddyfile.prd",
				adapterName: "",
			},
			want:    true,
			wantErr: false,
		},
		{

			name: "prefix of Caddyfile without ./ with any extension is Caddyfile",
			args: args{
				configFile:  "Caddyfile.prd",
				adapterName: "",
			},
			want:    true,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := isCaddyfile(tt.args.configFile, tt.args.adapterName)
			if (err != nil) != tt.wantErr {
				t.Errorf("isCaddyfile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("isCaddyfile() = %v, want %v", got, tt.want)
			}
		})
	}
}
