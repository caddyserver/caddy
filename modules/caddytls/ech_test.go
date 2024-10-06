package caddytls

import (
	"reflect"
	"testing"
)

func TestParseSvcParams(t *testing.T) {
	for i, test := range []struct {
		input     string
		expect    svcParams
		shouldErr bool
	}{
		{
			input: `alpn="h2,h3" no-default-alpn ipv6hint=2001:db8::1 port=443`,
			expect: svcParams{
				"alpn":            {"h2", "h3"},
				"no-default-alpn": {},
				"ipv6hint":        {"2001:db8::1"},
				"port":            {"443"},
			},
		},
		{
			input: `key=value quoted="some string" flag`,
			expect: svcParams{
				"key":    {"value"},
				"quoted": {"some string"},
				"flag":   {},
			},
		},
		{
			input: `key="nested \"quoted\" value,foobar"`,
			expect: svcParams{
				"key": {`nested "quoted" value`, "foobar"},
			},
		},
		{
			input: `alpn=h3,h2 tls-supported-groups=29,23 no-default-alpn ech="foobar"`,
			expect: svcParams{
				"alpn":                 {"h3", "h2"},
				"tls-supported-groups": {"29", "23"},
				"no-default-alpn":      {},
				"ech":                  {"foobar"},
			},
		},
		{
			input: `escape=\097`,
			expect: svcParams{
				"escape": {"a"},
			},
		},
		{
			input: `escapes=\097\098c`,
			expect: svcParams{
				"escapes": {"abc"},
			},
		},
	} {
		actual, err := parseSvcParams(test.input)
		if err != nil && !test.shouldErr {
			t.Errorf("Test %d: Expected no error, but got: %v (input=%q)", i, err, test.input)
			continue
		} else if err == nil && test.shouldErr {
			t.Errorf("Test %d: Expected an error, but got no error (input=%q)", i, test.input)
			continue
		}
		if !reflect.DeepEqual(test.expect, actual) {
			t.Errorf("Test %d: Expected %v, got %v (input=%q)", i, test.expect, actual, test.input)
			continue
		}
	}
}

func TestSvcParamsString(t *testing.T) {
	// this test relies on the parser also working
	// because we can't just compare string outputs
	// since map iteration is unordered
	for i, test := range []svcParams{

		{
			"alpn":            {"h2", "h3"},
			"no-default-alpn": {},
			"ipv6hint":        {"2001:db8::1"},
			"port":            {"443"},
		},

		{
			"key":    {"value"},
			"quoted": {"some string"},
			"flag":   {},
		},
		{
			"key": {`nested "quoted" value`, "foobar"},
		},
		{
			"alpn":                 {"h3", "h2"},
			"tls-supported-groups": {"29", "23"},
			"no-default-alpn":      {},
			"ech":                  {"foobar"},
		},
	} {
		combined := test.String()
		parsed, err := parseSvcParams(combined)
		if err != nil {
			t.Errorf("Test %d: Expected no error, but got: %v (input=%q)", i, err, test)
			continue
		}
		if len(parsed) != len(test) {
			t.Errorf("Test %d: Expected %d keys, but got %d", i, len(test), len(parsed))
			continue
		}
		for key, expectedVals := range test {
			if expected, actual := len(expectedVals), len(parsed[key]); expected != actual {
				t.Errorf("Test %d: Expected key %s to have %d values, but had %d", i, key, expected, actual)
				continue
			}
			for j, expected := range expectedVals {
				if actual := parsed[key][j]; actual != expected {
					t.Errorf("Test %d key %q value %d: Expected '%s' but got '%s'", i, key, j, expected, actual)
					continue
				}
			}
		}
		if !reflect.DeepEqual(parsed, test) {
			t.Errorf("Test %d: Expected %#v, got %#v", i, test, combined)
			continue
		}
	}
}
