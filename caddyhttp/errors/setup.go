// Copyright 2015 Light Code Labs, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package errors

import (
	"log"
	"os"
	"path/filepath"
	"strconv"

	"github.com/caddyserver/caddy"
	"github.com/caddyserver/caddy/caddyhttp/httpserver"
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

	optionalBlock := func() error {
		for c.NextBlock() {

			what := c.Val()
			where := c.RemainingArgs()

			if httpserver.IsLogRollerSubdirective(what) {
				var err error
				err = httpserver.ParseRoller(handler.Log.Roller, what, where...)
				if err != nil {
					return err
				}
			} else {
				if len(where) != 1 {
					return c.ArgErr()
				}
				where := where[0]

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
						return c.Errf("Duplicate status code entry: %s", what)
					}
					handler.GenericErrorPage = where
				} else {
					whatInt, err := strconv.Atoi(what)
					if err != nil {
						return c.Err("Expecting a numeric status code or '*', got '" + what + "'")
					}

					if _, exists := handler.ErrorPages[whatInt]; exists {
						return c.Errf("Duplicate status code entry: %s", what)
					}

					handler.ErrorPages[whatInt] = where
				}
			}
		}
		return nil
	}

	for c.Next() {
		// weird hack to avoid having the handler values overwritten.
		if c.Val() == "}" {
			continue
		}

		args := c.RemainingArgs()

		if len(args) == 1 {
			switch args[0] {
			case "visible":
				handler.Debug = true
			default:
				handler.Log.Output = args[0]
				handler.Log.Roller = httpserver.DefaultLogRoller()
			}
		}

		if len(args) > 1 {
			return handler, c.Errf("Only 1 Argument expected for errors directive")
		}

		// Configuration may be in a block
		err := optionalBlock()
		if err != nil {
			return handler, err
		}
	}

	return handler, nil
}
