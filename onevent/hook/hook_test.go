package hook

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/caddyserver/caddy"
	"github.com/google/uuid"
)

func TestHook(t *testing.T) {
	tempDirPath := os.TempDir()

	testDir := filepath.Join(tempDirPath, "temp_dir_for_testing_command")
	defer func() {
		// clean up after non-blocking startup function quits
		time.Sleep(500 * time.Millisecond)
		os.RemoveAll(testDir)
	}()
	osSensitiveTestDir := filepath.FromSlash(testDir)
	os.RemoveAll(osSensitiveTestDir) // start with a clean slate

	tests := []struct {
		name            string
		event           caddy.EventName
		command         string
		args            []string
		shouldErr       bool
		shouldRemoveErr bool
	}{
		{name: "blocking", event: caddy.InstanceStartupEvent, command: "mkdir", args: []string{osSensitiveTestDir}, shouldErr: false, shouldRemoveErr: false},
		{name: "nonBlocking", event: caddy.ShutdownEvent, command: "mkdir", args: []string{osSensitiveTestDir, "&"}, shouldErr: false, shouldRemoveErr: true},
		{name: "nonBlocking2", event: caddy.ShutdownEvent, command: "echo", args: []string{"&"}, shouldErr: false, shouldRemoveErr: true},
		{name: "nonExistent", event: caddy.CertRenewEvent, command: strconv.Itoa(int(time.Now().UnixNano())), shouldErr: true, shouldRemoveErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := new(Config)
			cfg.ID = uuid.New().String()
			cfg.Event = test.event
			cfg.Command = test.command
			cfg.Args = test.args

			err := cfg.Hook(test.event, nil)
			if err == nil && test.shouldErr {
				t.Error("Test didn't error, but it should have")
			} else if err != nil && !test.shouldErr {
				t.Errorf("Test errored, but it shouldn't have; got '%v'", err)
			}

			err = os.Remove(osSensitiveTestDir)
			if err != nil && !test.shouldRemoveErr {
				t.Errorf("Test received an error of:\n%v", err)
			}
		})
	}
}
