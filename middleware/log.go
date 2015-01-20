package middleware

import (
	"log"
	"net/http"
	"os"
)

func RequestLog(p parser) Middleware {
	var logWhat, outputFile, format string
	var logger *log.Logger

	for p.Next() {
		p.Args(&logWhat, &outputFile, &format)

		if logWhat == "" {
			return p.ArgErr()
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
	p.Startup(func() error {
		var err error
		var file *os.File

		if outputFile == "stdout" {
			file = os.Stdout
		} else if outputFile == "stderr" {
			file = os.Stderr
		} else {
			file, err = os.OpenFile(outputFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
			if err != nil {
				return err
			}
		}

		logger = log.New(file, "", 0)
		return nil
	})

	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			sw := newResponseRecorder(w)
			next(sw, r)
			rep := newReplacer(r, sw)
			logger.Println(rep.replace(format))
		}
	}
}

const (
	defaultLogFilename  = "access.log"
	commonLogFormat     = `{remote} ` + emptyStringReplacer + ` [{when}] "{method} {uri} {proto}" {status} {size}`
	combinedLogFormat   = commonLogFormat + ` "{>Referer}" "{>User-Agent}"`
	defaultReqLogFormat = commonLogFormat
)
