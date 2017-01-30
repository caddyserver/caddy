package errors

import (
	"log"
	"os"
	"path/filepath"
	"strconv"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

// setup configures a new errors middleware instance.
func setup(c *caddy.Controller) error {
	handler, err := errorsParse(c)

	if err != nil {
		return err
	}

	handler.Log.Attach(c)

	httpserver.GetConfig(c).AddMiddleware(func(next httpserver.Handler) httpserver.Handler {
		handler.Next = next
		return handler
	})

	return nil
}

func errorsParse(c *caddy.Controller) (*ErrorHandler, error) {

	// Very important that we make a pointer because the startup
	// function that opens the log file must have access to the
	// same instance of the handler, not a copy.
	handler := &ErrorHandler{
		ErrorPages: make(map[int]string),
		Log:        &httpserver.Logger{},
	}

	cfg := httpserver.GetConfig(c)

	optionalBlock := func() (bool, error) {
		var hadBlock bool

		for c.NextBlock() {
			hadBlock = true

			what := c.Val()
			if !c.NextArg() {
				return hadBlock, c.ArgErr()
			}
			where := c.Val()

			if what == "log" {
				if where == "visible" {
					handler.Debug = true
				} else {
					handler.Log.Output = where
					if c.NextArg() {
						if c.Val() == "{" {
							c.IncrNest()
							logRoller, err := httpserver.ParseRoller(c)
							if err != nil {
								return hadBlock, err
							}
							handler.Log.Roller = logRoller
						}
					}
				}
			} else {
				// Error page; ensure it exists
				if !filepath.IsAbs(where) {
					where = filepath.Join(cfg.Root, where)
				}

				f, err := os.Open(where)
				if err != nil {
					log.Printf("[WARNING] Unable to open error page '%s': %v", where, err)
				}
				f.Close()

				if what == "*" {
					if handler.GenericErrorPage != "" {
						return hadBlock, c.Errf("Duplicate status code entry: %s", what)
					}
					handler.GenericErrorPage = where
				} else {
					whatInt, err := strconv.Atoi(what)
					if err != nil {
						return hadBlock, c.Err("Expecting a numeric status code or '*', got '" + what + "'")
					}

					if _, exists := handler.ErrorPages[whatInt]; exists {
						return hadBlock, c.Errf("Duplicate status code entry: %s", what)
					}

					handler.ErrorPages[whatInt] = where
				}
			}
		}
		return hadBlock, nil
	}

	for c.Next() {
		// weird hack to avoid having the handler values overwritten.
		if c.Val() == "}" {
			continue
		}
		// Configuration may be in a block
		hadBlock, err := optionalBlock()
		if err != nil {
			return handler, err
		}

		// Otherwise, the only argument would be an error log file name or 'visible'
		if !hadBlock {
			if c.NextArg() {
				if c.Val() == "visible" {
					handler.Debug = true
				} else {
					handler.Log.Output = c.Val()
				}
			}
		}
	}

	return handler, nil
}
