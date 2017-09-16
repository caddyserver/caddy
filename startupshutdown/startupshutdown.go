package startupshutdown

import (
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/mholt/caddy"
)

func init() {
	caddy.RegisterPlugin("startup", caddy.Plugin{Action: Startup})
	caddy.RegisterPlugin("shutdown", caddy.Plugin{Action: Shutdown})
}

// Startup registers a startup callback to execute during server start.
func Startup(c *caddy.Controller) error {
	return registerCallback(c, c.OnFirstStartup)
}

// Shutdown registers a shutdown callback to execute during server stop.
func Shutdown(c *caddy.Controller) error {
	return registerCallback(c, c.OnFinalShutdown)
}

// registerCallback registers a callback function to execute by
// using c to parse the directive. It registers the callback
// to be executed using registerFunc.
func registerCallback(c *caddy.Controller, registerFunc func(func() error)) error {
	var funcs []func() error

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

		command, args, err := caddy.SplitCommandAndArgs(strings.Join(args, " "))
		if err != nil {
			return c.Err(err.Error())
		}

		fn := func() error {
			cmd := exec.Command(command, args...)
			cmd.Stdin = os.Stdin
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if nonblock {
				log.Printf("[INFO] Nonblocking Command:\"%s %s\"", command, strings.Join(args, " "))
				return cmd.Start()
			}
			log.Printf("[INFO] Blocking Command:\"%s %s\"", command, strings.Join(args, " "))
			return cmd.Run()
		}

		funcs = append(funcs, fn)
	}

	return c.OncePerServerBlock(func() error {
		for _, fn := range funcs {
			registerFunc(fn)
		}
		return nil
	})
}
