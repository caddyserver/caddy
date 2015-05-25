// Package log implements basic but useful request (access) logging middleware.
package log

import (
	"log"
	"net/http"

	"github.com/mholt/caddy/middleware"
)

// Logger is a basic request logging middleware.
type Logger struct {
	Next  middleware.Handler
	Rules []Rule
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

// Rule configures the logging middleware.
type Rule struct {
	PathScope  string
	OutputFile string
	Format     string
	Log        *log.Logger
}

const (
	DefaultLogFilename = "access.log"
	CommonLogFormat    = `{remote} ` + middleware.EmptyStringReplacer + ` [{when}] "{method} {uri} {proto}" {status} {size}`
	CombinedLogFormat  = CommonLogFormat + ` "{>Referer}" "{>User-Agent}"`
	DefaultLogFormat   = CommonLogFormat
)
