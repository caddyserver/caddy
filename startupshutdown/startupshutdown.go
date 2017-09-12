package startupshutdown

import (
	"strings"

	"github.com/google/uuid"
	"github.com/mholt/caddy"
	"github.com/mholt/caddy/command/hook"
)

func init() {
	caddy.RegisterPlugin("startup", caddy.Plugin{Action: Startup})
	caddy.RegisterPlugin("shutdown", caddy.Plugin{Action: Shutdown})
}

// Startup is an alias for command startup.
func Startup(c *caddy.Controller) error {
	config, err := commandParse(c, caddy.InstanceStartupEvent)
	if err != nil {
		return c.ArgErr()
	}

	// Register Event Hooks.
	for _, cfg := range config {
		caddy.RegisterEventHook("command-"+cfg.ID, cfg.Hook)
	}

	return nil
}

// Shutdown is an alias for command shutdown.
func Shutdown(c *caddy.Controller) error {
	config, err := commandParse(c, caddy.ShutdownEvent)
	if err != nil {
		return c.ArgErr()
	}

	// Register Event Hooks.
	for _, cfg := range config {
		caddy.RegisterEventHook("command-"+cfg.ID, cfg.Hook)
	}

	return nil
}

func commandParse(c *caddy.Controller, event caddy.EventName) ([]*hook.Config, error) {
	var config []*hook.Config

	for c.Next() {
		cfg := new(hook.Config)

		args := c.RemainingArgs()
		if len(args) == 0 {
			return config, c.ArgErr()
		}

		// Configure Event.
		cfg.Event = event

		// Assign an unique ID.
		cfg.ID = uuid.New().String()

		// Extract command and arguments.
		command, args, err := caddy.SplitCommandAndArgs(strings.Join(args, " "))
		if err != nil {
			return config, c.Err(err.Error())
		}

		cfg.Command = command
		cfg.Args = args

		config = append(config, cfg)
	}

	return config, nil
}
