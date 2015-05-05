package setup

import (
	"os"
	"os/exec"
	"strings"

	"github.com/mholt/caddy/middleware"
)

func Startup(c *Controller) (middleware.Middleware, error) {
	return nil, registerCallback(c, &c.Startup)
}

func Shutdown(c *Controller) (middleware.Middleware, error) {
	return nil, registerCallback(c, &c.Shutdown)
}

// registerCallback registers a callback function to execute by
// using c to parse the line. It appends the callback function
// to the list of callback functions passed in by reference.
func registerCallback(c *Controller, list *[]func() error) error {
	for c.Next() {
		args := c.RemainingArgs()
		if len(args) == 0 {
			return c.ArgErr()
		}

		nonblock := false
		if len(args) > 1 && args[len(args)-1] == "&" {
			// Run command in background; non-blocking
			nonblock = true
			args = args[:len(args)-1]
		}

		command, args, err := middleware.SplitCommandAndArgs(strings.Join(args, " "))
		if err != nil {
			return c.Err(err.Error())
		}

		fn := func() error {
			cmd := exec.Command(command, args...)
			cmd.Stdin = os.Stdin
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr

			if nonblock {
				return cmd.Start()
			} else {
				return cmd.Run()
			}
		}

		*list = append(*list, fn)
	}

	return nil
}
