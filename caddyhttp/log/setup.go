package log

import (
	"strings"

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

		path := "/"
		format := DefaultLogFormat
		output := DefaultLogFilename

		switch len(args) {
		case 0:
			// nothing to change
		case 1:
			// Only an output file specified
			output = args[0]
		case 2, 3:
			// Path scope, output file, and maybe a format specified
			path = args[0]
			output = args[1]
			if len(args) > 2 {
				format = strings.Replace(args[2], "{common}", CommonLogFormat, -1)
				format = strings.Replace(format, "{combined}", CombinedLogFormat, -1)
			}
		default:
			// Maximum number of args in log directive is 3.
			return nil, c.ArgErr()
		}

		rules = appendEntry(rules, path, &Entry{
			Log: &httpserver.Logger{
				Output: output,
				Roller: logRoller,
			},
			Format: format,
		})
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
