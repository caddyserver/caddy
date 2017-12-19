// Copyright 2015 Light Code Labs, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package log implements request (access) logging middleware.
package log

import (
	"fmt"
	"net"
	"net/http"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func init() {
	caddy.RegisterPlugin("log", caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	})
}

// Logger is a basic request logging middleware.
type Logger struct {
	Next      httpserver.Handler
	Rules     []*Rule
	ErrorFunc func(http.ResponseWriter, *http.Request, int) // failover error handler
}

func (l Logger) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	for _, rule := range l.Rules {
		if httpserver.Path(r.URL.Path).Matches(rule.PathScope) {
			// Record the response
			responseRecorder := httpserver.NewResponseRecorder(w)

			// Attach the Replacer we'll use so that other middlewares can
			// set their own placeholders if they want to.
			rep := httpserver.NewReplacer(r, responseRecorder, CommonLogEmptyValue)
			responseRecorder.Replacer = rep

			// Bon voyage, request!
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

			// Write log entries
			for _, e := range rule.Entries {

				// Mask IP Address
				if e.Log.IPMaskExists {
					hostip, _, err := net.SplitHostPort(r.RemoteAddr)
					if err == nil {
						maskedIP := e.Log.MaskIP(hostip)
						// Overwrite log value with Masked version
						rep.Set("remote", maskedIP)
					}
				}
				e.Log.Println(rep.Replace(e.Format))
			}

			return status, err
		}
	}
	return l.Next.ServeHTTP(w, r)
}

// Entry represents a log entry under a path scope
type Entry struct {
	Format string
	Log    *httpserver.Logger
}

// Rule configures the logging middleware.
type Rule struct {
	PathScope string
	Entries   []*Entry
}

const (
	// DefaultLogFilename is the default log filename.
	DefaultLogFilename = "access.log"
	// CommonLogFormat is the common log format.
	CommonLogFormat = `{remote} ` + CommonLogEmptyValue + ` {user} [{when}] "{method} {uri} {proto}" {status} {size}`
	// CommonLogEmptyValue is the common empty log value.
	CommonLogEmptyValue = "-"
	// CombinedLogFormat is the combined log format.
	CombinedLogFormat = CommonLogFormat + ` "{>Referer}" "{>User-Agent}"`
	// DefaultLogFormat is the default log format.
	DefaultLogFormat = CommonLogFormat
)
