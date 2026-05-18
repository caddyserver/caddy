package caddycmd

import (
	"errors"
	"net"
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

func TestListenTCPForPingbackUsesIPv4Loopback(t *testing.T) {
	var calls []string
	expected := &stubListener{addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}}

	actual, err := listenTCPForPingback(func(network, address string) (net.Listener, error) {
		calls = append(calls, network+" "+address)
		return expected, nil
	})
	if err != nil {
		t.Fatalf("listenTCPForPingback returned error: %v", err)
	}
	if actual != expected {
		t.Fatalf("expected listener %p, got %p", expected, actual)
	}

	expectCalls := []string{"tcp4 127.0.0.1:0"}
	if !reflect.DeepEqual(calls, expectCalls) {
		t.Fatalf("expected calls %v, got %v", expectCalls, calls)
	}
}

func TestListenTCPForPingbackFallsBackToIPv6Loopback(t *testing.T) {
	var calls []string
	expected := &stubListener{addr: &net.TCPAddr{IP: net.ParseIP("::1"), Port: 1234}}

	actual, err := listenTCPForPingback(func(network, address string) (net.Listener, error) {
		calls = append(calls, network+" "+address)
		if len(calls) == 1 {
			return nil, errors.New("ipv4 unavailable")
		}
		return expected, nil
	})
	if err != nil {
		t.Fatalf("listenTCPForPingback returned error: %v", err)
	}
	if actual != expected {
		t.Fatalf("expected listener %p, got %p", expected, actual)
	}

	expectCalls := []string{"tcp4 127.0.0.1:0", "tcp6 [::1]:0"}
	if !reflect.DeepEqual(calls, expectCalls) {
		t.Fatalf("expected calls %v, got %v", expectCalls, calls)
	}
}

func TestListenTCPForPingbackReportsBothFailures(t *testing.T) {
	_, err := listenTCPForPingback(func(network, address string) (net.Listener, error) {
		return nil, errors.New(network + " failed")
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "tcp4 failed") ||
		!strings.Contains(err.Error(), "tcp6 failed") {
		t.Fatalf("expected both listener errors, got: %v", err)
	}
}

type stubListener struct {
	addr net.Addr
}

func (sl *stubListener) Accept() (net.Conn, error) {
	return nil, net.ErrClosed
}

func (sl *stubListener) Close() error {
	return nil
}

func (sl *stubListener) Addr() net.Addr {
	return sl.addr
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
