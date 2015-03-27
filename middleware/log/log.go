// Package log implements basic but useful request logging middleware.
package log

import (
	"log"
	"net/http"
	"os"

	"github.com/mholt/caddy/middleware"
)

// New instantiates a new instance of logging middleware.
func New(c middleware.Controller) (middleware.Middleware, error) {
	var logWhat, outputFile, format string
	var logger *log.Logger

	for c.Next() {
		c.Args(&logWhat, &outputFile, &format)

		if logWhat == "" {
			return nil, c.ArgErr()
		}
		if outputFile == "" {
			outputFile = defaultLogFilename
		}
		switch format {
		case "":
			format = defaultReqLogFormat
		case "{common}":
			format = commonLogFormat
		case "{combined}":
			format = combinedLogFormat
		}
	}

	// Open the log file for writing when the server starts
	c.Startup(func() error {
		var err error
		var file *os.File

		if outputFile == "stdout" {
			file = os.Stdout
		} else if outputFile == "stderr" {
			file = os.Stderr
		} else {
			file, err = os.OpenFile(outputFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
			if err != nil {
				return err
			}
		}

		logger = log.New(file, "", 0)
		return nil
	})

	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			sw := middleware.NewResponseRecorder(w)
			next(sw, r)
			rep := middleware.NewReplacer(r, sw)
			logger.Println(rep.Replace(format))
		}
	}, nil
}

const (
	defaultLogFilename  = "access.log"
	commonLogFormat     = `{remote} ` + middleware.EmptyStringReplacer + ` [{when}] "{method} {uri} {proto}" {status} {size}`
	combinedLogFormat   = commonLogFormat + ` "{>Referer}" "{>User-Agent}"`
	defaultReqLogFormat = commonLogFormat
)
