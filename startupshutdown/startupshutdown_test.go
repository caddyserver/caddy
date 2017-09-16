package startupshutdown

import (
	"testing"

	"github.com/mholt/caddy"
)

func TestStartup(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		shouldErr bool
	}{
		{name: "noInput", input: "startup", shouldErr: true},
		{name: "startup", input: "startup cmd arg", shouldErr: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := caddy.NewTestController("", test.input)

			err := Startup(c)
			if err == nil && test.shouldErr {
				t.Error("Test didn't error, but it should have")
			} else if err != nil && !test.shouldErr {
				t.Errorf("Test errored, but it shouldn't have; got '%v'", err)
			}
		})
	}
}

func TestShutdown(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		shouldErr bool
	}{
		{name: "noInput", input: "shutdown", shouldErr: true},
		{name: "shutdown", input: "shutdown cmd arg", shouldErr: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := caddy.NewTestController("", test.input)

			err := Shutdown(c)
			if err == nil && test.shouldErr {
				t.Error("Test didn't error, but it should have")
			} else if err != nil && !test.shouldErr {
				t.Errorf("Test errored, but it shouldn't have; got '%v'", err)
			}
		})
	}
}