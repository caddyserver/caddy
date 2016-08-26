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
		for _, rule := range rules {
			for _, entry := range rule.Entries {
				var err error
				var writer io.Writer

				if entry.OutputFile == "stdout" {
					writer = os.Stdout
				} else if entry.OutputFile == "stderr" {
					writer = os.Stderr
				} else if entry.OutputFile == "syslog" {
					writer, err = gsyslog.NewLogger(gsyslog.LOG_INFO, "LOCAL0", "caddy")
					if err != nil {
						return err
					}
				} else {
					err := os.MkdirAll(filepath.Dir(entry.OutputFile), 0744)
					if err != nil {
						return err
					}
					file, err := os.OpenFile(entry.OutputFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
					if err != nil {
						return err
					}
					if entry.Roller != nil {
						file.Close()
						entry.Roller.Filename = entry.OutputFile
						writer = entry.Roller.GetLogWriter()
					} else {
						entry.file = file
						writer = file
					}
				}

				entry.Log = log.New(writer, "", 0)
			}
		}

		return nil
	})

	// When server stops, close any open log files
	c.OnShutdown(func() error {
		for _, rule := range rules {
			for _, entry := range rule.Entries {
				if entry.file != nil {
					entry.file.Close()
				}
			}
		}
		return nil
	})

	httpserver.GetConfig(c).AddMiddleware(func(next httpserver.Handler) httpserver.Handler {
		return Logger{Next: next, Rules: rules, ErrorFunc: httpserver.DefaultErrorFunc}
	})

	return nil
}

func logParse(c *caddy.Controller) ([]*Rule, error) {
	var rules []*Rule

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
			rules = appendEntry(rules, "/", &Entry{
				OutputFile: DefaultLogFilename,
				Format:     DefaultLogFormat,
				Roller:     logRoller,
			})
		} else if len(args) == 1 {
			// Only an output file specified
			rules = appendEntry(rules, "/", &Entry{
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

			rules = appendEntry(rules, args[0], &Entry{
				OutputFile: args[1],
				Format:     format,
				Roller:     logRoller,
			})
		}
	}

	return rules, nil
}

func appendEntry(rules []*Rule, pathScope string, entry *Entry) []*Rule {
	for _, rule := range rules {
		if rule.PathScope == pathScope {
			rule.Entries = append(rule.Entries, entry)
			return rules
		}
	}

	rules = append(rules, &Rule{
		PathScope: pathScope,
		Entries:   []*Entry{entry},
	})

	return rules
}
