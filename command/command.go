package command

import (
	"strings"

	"github.com/google/uuid"
	"github.com/mholt/caddy"
	"github.com/mholt/caddy/command/hook"
)

func init() {
	// Register Directive.
	caddy.RegisterPlugin("command", caddy.Plugin{Action: setup})
}

func setup(c *caddy.Controller) error {
	config, err := commandParse(c)
	if err != nil {
		return err
	}

	// Register Event Hooks.
	for _, cfg := range config {
		caddy.RegisterEventHook("command-"+cfg.ID, cfg.Hook)
	}

	return nil
}

func commandParse(c *caddy.Controller) ([]*hook.Config, error) {
	var config []*hook.Config

	for c.Next() {
		cfg := new(hook.Config)

		if !c.NextArg() {
			return config, c.ArgErr()
		}

		// Configure Event.
		event, ok := hook.SupportedEvents[strings.ToLower(c.Val())]
		if !ok {
			return config, c.Errf("Wrong event name or event not supported: '%s'", c.Val())
		}
		cfg.Event = event

		// Assign an unique ID.
		cfg.ID = uuid.New().String()

		// Extract commands and arguments.
		args := c.RemainingArgs()

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
