package setup

import (
	"io"
	"log"
	"os"

	"github.com/hashicorp/go-syslog"
	"github.com/mholt/caddy/middleware"
	caddylog "github.com/mholt/caddy/middleware/log"
	"github.com/mholt/caddy/server"
)

// Log sets up the logging middleware.
func Log(c *Controller) (middleware.Middleware, error) {
	rules, err := logParse(c)
	if err != nil {
		return nil, err
	}

	// Open the log files for writing when the server starts
	c.Startup = append(c.Startup, func() error {
		for i := 0; i < len(rules); i++ {
			var err error
			var writer io.Writer

			if rules[i].OutputFile == "stdout" {
				writer = os.Stdout
			} else if rules[i].OutputFile == "stderr" {
				writer = os.Stderr
			} else if rules[i].OutputFile == "syslog" {
				writer, err = gsyslog.NewLogger(gsyslog.LOG_INFO, "LOCAL0", "caddy")
				if err != nil {
					return err
				}
			} else {
				var file *os.File
				file, err = os.OpenFile(rules[i].OutputFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
				if err != nil {
					return err
				}
				if rules[i].Roller != nil {
					file.Close()
					rules[i].Roller.Filename = rules[i].OutputFile
					writer = rules[i].Roller.GetLogWriter()
				} else {
					writer = file
				}
			}

			rules[i].Log = log.New(writer, "", 0)
		}

		return nil
	})

	return func(next middleware.Handler) middleware.Handler {
		return caddylog.Logger{Next: next, Rules: rules, ErrorFunc: server.DefaultErrorFunc}
	}, nil
}

func logParse(c *Controller) ([]caddylog.Rule, error) {
	var rules []caddylog.Rule

	for c.Next() {
		args := c.RemainingArgs()

		var logRoller *middleware.LogRoller
		if c.NextBlock() {
			if c.Val() == "rotate" {
				if c.NextArg() {
					if c.Val() == "{" {
						var err error
						logRoller, err = parseRoller(c)
						if err != nil {
							return nil, err
						}
						// This part doesn't allow having something after the rotate block
						if c.Next() {
							if c.Val() != "}" {
								return nil, c.ArgErr()
							}
						}
					}
				}
			}
		}
		if len(args) == 0 {
			// Nothing specified; use defaults
			rules = append(rules, caddylog.Rule{
				PathScope:  "/",
				OutputFile: caddylog.DefaultLogFilename,
				Format:     caddylog.DefaultLogFormat,
				Roller:     logRoller,
			})
		} else if len(args) == 1 {
			// Only an output file specified
			rules = append(rules, caddylog.Rule{
				PathScope:  "/",
				OutputFile: args[0],
				Format:     caddylog.DefaultLogFormat,
				Roller:     logRoller,
			})
		} else {
			// Path scope, output file, and maybe a format specified

			format := caddylog.DefaultLogFormat

			if len(args) > 2 {
				switch args[2] {
				case "{common}":
					format = caddylog.CommonLogFormat
				case "{combined}":
					format = caddylog.CombinedLogFormat
				default:
					format = args[2]
				}
			}

			rules = append(rules, caddylog.Rule{
				PathScope:  args[0],
				OutputFile: args[1],
				Format:     format,
				Roller:     logRoller,
			})
		}
	}

	return rules, nil
}
