package hook

import (
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/mholt/caddy"
)

// Hook executes a command.
func (cfg *Config) Hook(event caddy.EventName, info interface{}) error {
	if event != cfg.Event {
		return nil
	}

	nonblock := false
	if len(cfg.Args) >= 1 && cfg.Args[len(cfg.Args)-1] == "&" {
		// Run command in background; non-blocking
		nonblock = true
		cfg.Args = cfg.Args[:len(cfg.Args)-1]
	}

	// Execute command.
	cmd := exec.Command(cfg.Command, cfg.Args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if nonblock {
		log.Printf("[INFO] Nonblocking Command \"%s %s\" with ID %s", cfg.Command, strings.Join(cfg.Args, " "), cfg.ID)
		return cmd.Start()
	}
	log.Printf("[INFO] Blocking Command \"%s %s\" with ID %s", cfg.Command, strings.Join(cfg.Args, " "), cfg.ID)
	err := cmd.Run()
	if err != nil {
		return err
	}

	return nil
}
