package middleware

import (
	"log"
	"net/http"
)

func RequestLog(logger *log.Logger, format string) Middleware {
	if format == "" {
		format = defaultReqLogFormat
	}
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			sw := newResponseRecorder(w)
			next(sw, r)
			rep := newReplacer(r, sw)
			logger.Println(rep.replace(format))
		}
	}
}

// TODO.
func ErrorLog(logger *log.Logger, format string) Middleware {
	if format == "" {
		format = defaultErrLogFormat
	}
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			sw := newResponseRecorder(w)
			next(sw, r)
			// This is still TODO -- we need to define what constitutes an error to be logged
			//logger.Println("TODO")
		}
	}
}

const (
	commonLogFormat     = `{remote} ` + emptyStringReplacer + ` [{time}] "{method} {uri} {proto}" {status} {size}`
	combinedLogFormat   = commonLogFormat + ` "{>Referer}" "{>User-Agent}"`
	defaultReqLogFormat = commonLogFormat
	defaultErrLogFormat = "[TODO]"
)
