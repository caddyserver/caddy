// Copyright 2015 Matthew Holt and The Caddy Authors
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

package httplog

import (
	"net/http"
	"strconv"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Log{})
}

// Log implements a simple logging middleware.
type Log struct {
	LogName string `json:"log_name,omitempty"`
	logger  *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (Log) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		Name: "http.handlers.log",
		New:  func() caddy.Module { return new(Log) },
	}
}

// Provision sets up the log handler.
func (l *Log) Provision(ctx caddy.Context) error {
	l.logger = ctx.Logger(l)
	return nil
}

func (l *Log) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	repl := r.Context().Value(caddy.ReplacerCtxKey).(caddy.Replacer)

	wrec := caddyhttp.NewResponseRecorder(w, nil, nil)

	start := time.Now()
	if err := next.ServeHTTP(wrec, r); err != nil {
		return err
	}
	latency := time.Since(start)

	repl.Set("http.response.status", strconv.Itoa(wrec.Status()))
	repl.Set("http.response.size", strconv.Itoa(wrec.Size()))
	repl.Set("http.response.latency", latency.String())

	l.logger.Named(l.LogName).Info("request",
		zap.String("common_log", repl.ReplaceAll(CommonLogFormat, "-")),
		zap.Object("request", LoggableHTTPRequest(*r)),
		zap.Duration("latency", latency),
		zap.Int("size", wrec.Size()),
		zap.Int("status", wrec.Status()),
	)

	return nil
}

const (
	// CommonLogFormat is the common log format. https://en.wikipedia.org/wiki/Common_Log_Format
	CommonLogFormat = `{http.request.remote.host} ` + CommonLogEmptyValue + ` {http.handlers.authentication.user.id} [{time.now.common_log}] "{http.request.method} {http.request.orig_uri} {http.request.proto}" {http.response.status} {http.response.size}`

	// CommonLogEmptyValue is the common empty log value.
	CommonLogEmptyValue = "-"
)

// Interface guard
var _ caddyhttp.MiddlewareHandler = (*Log)(nil)
