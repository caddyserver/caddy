// Package log implements basic but useful request (access) logging middleware.
package log

import (
	"log"
	"net/http"
	"os"

	"github.com/mholt/caddy/middleware"
)

// New instantiates a new instance of logging middleware.
func New(c middleware.Controller) (middleware.Middleware, error) {
	rules, err := parse(c)
	if err != nil {
		return nil, err
	}

	// Open the log files for writing when the server starts
	c.Startup(func() error {
		for i := 0; i < len(rules); i++ {
			var err error
			var file *os.File

			if rules[i].OutputFile == "stdout" {
				file = os.Stdout
			} else if rules[i].OutputFile == "stderr" {
				file = os.Stderr
			} else {
				file, err = os.OpenFile(rules[i].OutputFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
				if err != nil {
					return err
				}
			}

			rules[i].Log = log.New(file, "", 0)
		}

		return nil
	})

	return func(next middleware.Handler) middleware.Handler {
		return Logger{Next: next, Rules: rules}
	}, nil
}

func (l Logger) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	for _, rule := range l.Rules {
		if middleware.Path(r.URL.Path).Matches(rule.PathScope) {
			responseRecorder := middleware.NewResponseRecorder(w)
			status, err := l.Next.ServeHTTP(responseRecorder, r)
			rep := middleware.NewReplacer(r, responseRecorder)
			rule.Log.Println(rep.Replace(rule.Format))
			return status, err
		}
	}
	return l.Next.ServeHTTP(w, r)
}

func parse(c middleware.Controller) ([]LogRule, error) {
	var rules []LogRule

	for c.Next() {
		args := c.RemainingArgs()

		if len(args) == 0 {
			// Nothing specified; use defaults
			rules = append(rules, LogRule{
				PathScope:  "/",
				OutputFile: defaultLogFilename,
				Format:     defaultLogFormat,
			})
		} else if len(args) == 1 {
			// Only an output file specified
			rules = append(rules, LogRule{
				PathScope:  "/",
				OutputFile: args[0],
				Format:     defaultLogFormat,
			})
		} else {
			// Path scope, output file, and maybe a format specified

			format := defaultLogFormat

			if len(args) > 2 {
				switch args[2] {
				case "{common}":
					format = commonLogFormat
				case "{combined}":
					format = combinedLogFormat
				default:
					format = args[2]
				}
			}

			rules = append(rules, LogRule{
				PathScope:  args[0],
				OutputFile: args[1],
				Format:     format,
			})
		}
	}

	return rules, nil
}

type Logger struct {
	Next  middleware.Handler
	Rules []LogRule
}

type LogRule struct {
	PathScope  string
	OutputFile string
	Format     string
	Log        *log.Logger
}

const (
	defaultLogFilename = "access.log"
	commonLogFormat    = `{remote} ` + middleware.EmptyStringReplacer + ` [{when}] "{method} {uri} {proto}" {status} {size}`
	combinedLogFormat  = commonLogFormat + ` "{>Referer}" "{>User-Agent}"`
	defaultLogFormat   = commonLogFormat
)
