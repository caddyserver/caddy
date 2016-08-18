package log

import (
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/hashicorp/go-syslog"
	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

// setup sets up the logging middleware.
func setup(c *caddy.Controller) error {
	rules, err := logParse(c)
	if err != nil {
		return err
	}

	// Open the log files for writing when the server starts
	c.OnStartup(func() error {
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
				err := os.MkdirAll(filepath.Dir(rules[i].OutputFile), 0744)
				if err != nil {
					return err
				}
				file, err := os.OpenFile(rules[i].OutputFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
				if err != nil {
					return err
				}
				if rules[i].Roller != nil {
					file.Close()
					rules[i].Roller.Filename = rules[i].OutputFile
					writer = rules[i].Roller.GetLogWriter()
				} else {
					rules[i].file = file
					writer = file
				}
			}

			rules[i].Log = log.New(writer, "", 0)
		}

		return nil
	})

	// When server stops, close any open log files
	c.OnShutdown(func() error {
		for _, rule := range rules {
			if rule.file != nil {
				rule.file.Close()
			}
		}
		return nil
	})

	httpserver.GetConfig(c).AddMiddleware(func(next httpserver.Handler) httpserver.Handler {
		return Logger{Next: next, Rules: rules, ErrorFunc: httpserver.DefaultErrorFunc}
	})

	return nil
}

func logParse(c *caddy.Controller) ([]Rule, error) {
	var rules []Rule

	for c.Next() {
		args := c.RemainingArgs()

		var logRoller *httpserver.LogRoller
		if c.NextBlock() {
			if c.Val() == "rotate" {
				if c.NextArg() {
					if c.Val() == "{" {
						var err error
						logRoller, err = httpserver.ParseRoller(c)
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
			rules = append(rules, Rule{
				PathScope:  "/",
				OutputFile: DefaultLogFilename,
				Format:     DefaultLogFormat,
				Roller:     logRoller,
			})
		} else if len(args) == 1 {
			// Only an output file specified
			rules = append(rules, Rule{
				PathScope:  "/",
				OutputFile: args[0],
				Format:     DefaultLogFormat,
				Roller:     logRoller,
			})
		} else {
			// Path scope, output file, and maybe a format specified

			format := DefaultLogFormat

			if len(args) > 2 {
				switch args[2] {
				case "{common}":
					format = CommonLogFormat
				case "{combined}":
					format = CombinedLogFormat
				default:
					format = args[2]
				}
			}

			rules = append(rules, Rule{
				PathScope:  args[0],
				OutputFile: args[1],
				Format:     format,
				Roller:     logRoller,
			})
		}
	}

	return rules, nil
}
