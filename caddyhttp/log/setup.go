package log

import (
	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

// setup sets up the logging middleware.
func setup(c *caddy.Controller) error {
	rules, err := logParse(c)
	if err != nil {
		return err
	}

	for _, rule := range rules {
		for _, entry := range rule.Entries {
			entry.Log.Attach(c)
		}
	}

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
		logRoller = httpserver.DefaultLogRoller()

		for c.NextBlock() {
			what := c.Val()
			if !c.NextArg() {
				return nil, c.ArgErr()
			}
			where := c.Val()

			// only support roller related options inside a block
			if !httpserver.IsLogRollerSubdirective(what) {
				return nil, c.ArgErr()
			}

			if err := httpserver.ParseRoller(logRoller, what, where); err != nil {
				return nil, err
			}
		}

		if len(args) == 0 {
			// Nothing specified; use defaults
			rules = appendEntry(rules, "/", &Entry{
				Log: &httpserver.Logger{
					Output: DefaultLogFilename,
					Roller: logRoller,
				},
				Format: DefaultLogFormat,
			})
		} else if len(args) == 1 {
			// Only an output file specified
			rules = appendEntry(rules, "/", &Entry{
				Log: &httpserver.Logger{
					Output: args[0],
					Roller: logRoller,
				},
				Format: DefaultLogFormat,
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
				Log: &httpserver.Logger{
					Output: args[1],
					Roller: logRoller,
				},
				Format: format,
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
