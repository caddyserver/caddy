package onevent

import (
	"testing"

	"github.com/caddyserver/caddy"
	"github.com/caddyserver/caddy/onevent/hook"
)

func TestSetup(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		shouldErr bool
	}{
		{name: "noInput", input: "on", shouldErr: true},
		{name: "nonExistent", input: "on xyz cmd arg", shouldErr: true},
		{name: "startup", input: "on startup cmd arg", shouldErr: false},
		{name: "shutdown", input: "on shutdown cmd arg &", shouldErr: false},
		{name: "certrenew", input: "on certrenew cmd arg", shouldErr: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := caddy.NewTestController("http", test.input)
			c.Key = test.name

			err := setup(c)

			if err == nil && test.shouldErr {
				t.Error("Test didn't error, but it should have")
			} else if err != nil && !test.shouldErr {
				t.Errorf("Test errored, but it shouldn't have; got '%v'", err)
			}
		})
	}
}

func TestCommandParse(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		shouldErr bool
		config    hook.Config
	}{
		{name: "noInput", input: `on`, shouldErr: true},
		{name: "nonExistent", input: "on xyz cmd arg", shouldErr: true},
		{name: "startup", input: `on startup cmd arg1 arg2`, shouldErr: false, config: hook.Config{Event: caddy.InstanceStartupEvent, Command: "cmd", Args: []string{"arg1", "arg2"}}},
		{name: "shutdown", input: `on shutdown cmd arg1 arg2 &`, shouldErr: false, config: hook.Config{Event: caddy.ShutdownEvent, Command: "cmd", Args: []string{"arg1", "arg2", "&"}}},
		{name: "certrenew", input: `on certrenew cmd arg1 arg2`, shouldErr: false, config: hook.Config{Event: caddy.CertRenewEvent, Command: "cmd", Args: []string{"arg1", "arg2"}}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config, err := onParse(caddy.NewTestController("http", test.input))

			if err == nil && test.shouldErr {
				t.Error("Test didn't error, but it should have")
			} else if err != nil && !test.shouldErr {
				t.Errorf("Test errored, but it shouldn't have; got '%v'", err)
			}

			for _, cfg := range config {
				if cfg.Event != test.config.Event {
					t.Errorf("Expected event %s; got %s", test.config.Event, cfg.Event)
				}

				if cfg.Command != test.config.Command {
					t.Errorf("Expected command %s; got %s", test.config.Command, cfg.Command)
				}

				for i, arg := range cfg.Args {
					if arg != test.config.Args[i] {
						t.Errorf("Expected arg in position %d to be %s, got %s", i, test.config.Args[i], arg)
					}
				}

			}
		})
	}
}
