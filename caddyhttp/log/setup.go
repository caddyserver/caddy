package log

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"

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
				err := OpenLogFile(entry)
				if err != nil {
					return err
				}
			}
		}

		return nil
	})

	// When server stops, close any open log files
	c.OnShutdown(func() error {
		for _, rule := range rules {
			for _, entry := range rule.Entries {
				if entry.file != nil {
					entry.fileMu.Lock()
					entry.file.Close()
					entry.fileMu.Unlock()
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

func OpenLogFile(e *Entry) error {

	var err error
	var writer io.Writer

	if e.OutputFile == "stdout" {
		writer = os.Stdout
	} else if e.OutputFile == "stderr" {
		writer = os.Stderr
	} else if e.OutputFile == "syslog" {
		writer, err = gsyslog.NewLogger(gsyslog.LOG_INFO, "LOCAL0", "caddy")
		if err != nil {
			return err
		}
	} else {
		err := os.MkdirAll(filepath.Dir(e.OutputFile), 0744)
		if err != nil {
			return err
		}
		file, err := os.OpenFile(e.OutputFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
		if err != nil {
			return err
		}
		if e.Roller != nil {
			file.Close()
			e.Roller.Filename = e.OutputFile
			writer = e.Roller.GetLogWriter()
		} else {
			e.file = file
			writer = file
		}
	}

	e.Log = log.New(writer, "", 0)
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
				fileMu:     new(sync.RWMutex),
			})
		} else if len(args) == 1 {
			log.Println("%v", args[0])
			// Only an output file specified
			rules = appendEntry(rules, "/", &Entry{
				OutputFile: args[0],
				Format:     DefaultLogFormat,
				Roller:     logRoller,
				fileMu:     new(sync.RWMutex),
			})
		} else {
			// Path scope, output file, and maybe a format specified
			log.Println("%v", args[1])

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
				fileMu:     new(sync.RWMutex),
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
