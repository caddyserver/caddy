package caddyhttp

import (
	"reflect"
	"testing"
)

func TestParseListenerAddr(t *testing.T) {
	for i, tc := range []struct {
		input       string
		expectProto string
		expectAddrs []string
		expectErr   bool
	}{
		{
			input:       "",
			expectProto: "tcp",
			expectErr:   true,
		},
		{
			input:       ":",
			expectProto: "tcp",
			expectErr:   true,
		},
		{
			input:       ":1234",
			expectProto: "tcp",
			expectAddrs: []string{":1234"},
		},
		{
			input:       "tcp::::1234",
			expectProto: "tcp",
			expectAddrs: []string{":1234"},
		},
		{
			input:       "tcp6::::1234",
			expectProto: "tcp6",
			expectAddrs: []string{":1234"},
		},
		{
			input:       "tcp4:::localhost:1234",
			expectProto: "tcp4",
			expectAddrs: []string{"localhost:1234"},
		},
		{
			input:       "unix:::localhost:1234-1236",
			expectProto: "unix",
			expectAddrs: []string{"localhost:1234", "localhost:1235", "localhost:1236"},
		},
		{
			input:       "localhost:1234-1234",
			expectProto: "tcp",
			expectAddrs: []string{"localhost:1234"},
		},
		{
			input:       "localhost:2-1",
			expectProto: "tcp",
			expectErr:   true,
		},
		{
			input:       "localhost:0",
			expectProto: "tcp",
			expectAddrs: []string{"localhost:0"},
		},
	} {
		actualProto, actualAddrs, err := parseListenAddr(tc.input)
		if tc.expectErr && err == nil {
			t.Errorf("Test %d: Expected error but got: %v", i, err)
		}
		if !tc.expectErr && err != nil {
			t.Errorf("Test %d: Expected no error but got: %v", i, err)
		}
		if actualProto != tc.expectProto {
			t.Errorf("Test %d: Expeceted protocol '%s' but got '%s'", i, tc.expectProto, actualProto)
		}
		if !reflect.DeepEqual(tc.expectAddrs, actualAddrs) {
			t.Errorf("Test %d: Expected addresses %v but got %v", i, tc.expectAddrs, actualAddrs)
		}
	}
}
