package errors

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/hashicorp/go-syslog"
	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

// setup configures a new errors middleware instance.
func setup(c *caddy.Controller) error {
	handler, err := errorsParse(c)
	if err != nil {
		return err
	}

	// Open the log file for writing when the server starts
	c.OnStartup(func() error {
		var err error
		var writer io.Writer

		switch handler.LogFile {
		case "visible":
			handler.Debug = true
		case "stdout":
			writer = os.Stdout
		case "stderr":
			writer = os.Stderr
		case "syslog":
			writer, err = gsyslog.NewLogger(gsyslog.LOG_ERR, "LOCAL0", "caddy")
			if err != nil {
				return err
			}
		default:
			if handler.LogFile == "" {
				writer = os.Stderr // default
				break
			}

			var file *os.File
			file, err = os.OpenFile(handler.LogFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
			if err != nil {
				return err
			}
			if handler.LogRoller != nil {
				file.Close()
				handler.LogRoller.Filename = handler.LogFile
				writer = handler.LogRoller.GetLogWriter()
			} else {
				handler.file = file
				writer = file
			}
		}

		handler.Log = log.New(writer, "", 0)
		return nil
	})

	// When server stops, close any open log file
	c.OnShutdown(func() error {
		if handler.file != nil {
			handler.fileMu.Lock()
			handler.file.Close()
			handler.fileMu.Unlock()
		}
		return nil
	})

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
	handler := &ErrorHandler{ErrorPages: make(map[int]string), fileMu: new(sync.RWMutex)}

	cfg := httpserver.GetConfig(c)

	optionalBlock := func() error {
		for c.NextBlock() {

			what := c.Val()
			if !c.NextArg() {
				return c.ArgErr()
			}
			where := c.Val()

			if httpserver.IsLogRollerSubdirective(what) {
				var err error
				err = httpserver.ParseRoller(handler.LogRoller, what, where)
				if err != nil {
					return err
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
				handler.LogFile = args[0]
				handler.LogRoller = httpserver.DefaultLogRoller()
			}
		}

		// Configuration may be in a block
		err := optionalBlock()
		if err != nil {
			return handler, err
		}
	}

	return handler, nil
}
