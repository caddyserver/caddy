// Package log implements basic but useful request (access) logging middleware.
package log

import (
	"fmt"
	"log"
	"net/http"

	"github.com/mholt/caddy/middleware"
)

// Logger is a basic request logging middleware.
type Logger struct {
	Next      middleware.Handler
	Rules     []Rule
	ErrorFunc func(http.ResponseWriter, *http.Request, int) // failover error handler
}

func (l Logger) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	for _, rule := range l.Rules {
		if middleware.Path(r.URL.Path).Matches(rule.PathScope) {
			responseRecorder := middleware.NewResponseRecorder(w)
			status, err := l.Next.ServeHTTP(responseRecorder, r)
			if status >= 400 {
				// There was an error up the chain, but no response has been written yet.
				// The error must be handled here so the log entry will record the response size.
				if l.ErrorFunc != nil {
					l.ErrorFunc(responseRecorder, r, status)
				} else {
					// Default failover error handler
					responseRecorder.WriteHeader(status)
					fmt.Fprintf(responseRecorder, "%d %s", status, http.StatusText(status))
				}
				status = 0
			}
			rep := middleware.NewReplacer(r, responseRecorder, CommonLogEmptyValue)
			rule.Log.Println(rep.Replace(rule.Format))
			return status, err
		}
	}
	return l.Next.ServeHTTP(w, r)
}

// Rule configures the logging middleware.
type Rule struct {
	PathScope  string
	OutputFile string
	Format     string
	Log        *log.Logger
}

const (
	DefaultLogFilename  = "access.log"
	CommonLogFormat     = `{remote} ` + CommonLogEmptyValue + ` [{when}] "{method} {uri} {proto}" {status} {size}`
	CommonLogEmptyValue = "-"
	CombinedLogFormat   = CommonLogFormat + ` "{>Referer}" "{>User-Agent}"`
	DefaultLogFormat    = CommonLogFormat
)
