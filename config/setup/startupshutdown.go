package setup

import (
	"os"
	"os/exec"

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
		if !c.NextArg() {
			return c.ArgErr()
		}

		command, args, err := middleware.SplitCommandAndArgs(c.Val())
		if err != nil {
			return c.Err(err.Error())
		}

		fn := func() error {
			cmd := exec.Command(command, args...)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			return cmd.Run()
		}

		*list = append(*list, fn)
	}

	return nil
}
