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

package caddyhttp

import (
	"errors"
	"net"
	"net/http"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/caddyserver/caddy/v2"
)

// ServerLogConfig describes a server's logging configuration. If
// enabled without customization, all requests to this server are
// logged to the default logger; logger destinations may be
// customized per-request-host.
type ServerLogConfig struct {
	// The default logger name for all logs emitted by this server for
	// hostnames that are not in the LoggerNames (logger_names) map.
	DefaultLoggerName string `json:"default_logger_name,omitempty"`

	// LoggerNames maps request hostnames to a custom logger name.
	// For example, a mapping of "example.com" to "example" would
	// cause access logs from requests with a Host of example.com
	// to be emitted by a logger named "http.log.access.example".
	LoggerNames map[string]string `json:"logger_names,omitempty"`

	// By default, all requests to this server will be logged if
	// access logging is enabled. This field lists the request
	// hosts for which access logging should be disabled.
	SkipHosts []string `json:"skip_hosts,omitempty"`

	// If true, requests to any host not appearing in the
	// LoggerNames (logger_names) map will not be logged.
	SkipUnmappedHosts bool `json:"skip_unmapped_hosts,omitempty"`

	// If true, credentials that are otherwise omitted, will be logged.
	// The definition of credentials is defined by https://fetch.spec.whatwg.org/#credentials,
	// and this includes some request and response headers, i.e `Cookie`,
	// `Set-Cookie`, `Authorization`, and `Proxy-Authorization`.
	ShouldLogCredentials bool `json:"should_log_credentials,omitempty"`
}

// wrapLogger wraps logger in a logger named according to user preferences for the given host.
func (slc ServerLogConfig) wrapLogger(logger *zap.Logger, host string) *zap.Logger {
	if loggerName := slc.getLoggerName(host); loggerName != "" {
		return logger.Named(loggerName)
	}
	return logger
}

func (slc ServerLogConfig) getLoggerName(host string) string {
	tryHost := func(key string) (string, bool) {
		// first try exact match
		if loggerName, ok := slc.LoggerNames[key]; ok {
			return loggerName, ok
		}
		// strip port and try again (i.e. Host header of "example.com:1234" should
		// match "example.com" if there is no "example.com:1234" in the map)
		hostOnly, _, err := net.SplitHostPort(key)
		if err != nil {
			return "", false
		}
		loggerName, ok := slc.LoggerNames[hostOnly]
		return loggerName, ok
	}

	// try the exact hostname first
	if loggerName, ok := tryHost(host); ok {
		return loggerName
	}

	// try matching wildcard domains if other non-specific loggers exist
	labels := strings.Split(host, ".")
	for i := range labels {
		if labels[i] == "" {
			continue
		}
		labels[i] = "*"
		wildcardHost := strings.Join(labels, ".")
		if loggerName, ok := tryHost(wildcardHost); ok {
			return loggerName
		}
	}

	return slc.DefaultLoggerName
}

func (slc *ServerLogConfig) clone() *ServerLogConfig {
	clone := &ServerLogConfig{
		DefaultLoggerName:    slc.DefaultLoggerName,
		LoggerNames:          make(map[string]string),
		SkipHosts:            append([]string{}, slc.SkipHosts...),
		SkipUnmappedHosts:    slc.SkipUnmappedHosts,
		ShouldLogCredentials: slc.ShouldLogCredentials,
	}
	for k, v := range slc.LoggerNames {
		clone.LoggerNames[k] = v
	}
	return clone
}

// errLogValues inspects err and returns the status code
// to use, the error log message, and any extra fields.
// If err is a HandlerError, the returned values will
// have richer information.
func errLogValues(err error) (status int, msg string, fields []zapcore.Field) {
	var handlerErr HandlerError
	if errors.As(err, &handlerErr) {
		status = handlerErr.StatusCode
		if handlerErr.Err == nil {
			msg = err.Error()
		} else {
			msg = handlerErr.Err.Error()
		}
		fields = []zapcore.Field{
			zap.Int("status", handlerErr.StatusCode),
			zap.String("err_id", handlerErr.ID),
			zap.String("err_trace", handlerErr.Trace),
		}
		return
	}
	status = http.StatusInternalServerError
	msg = err.Error()
	return
}

// ExtraLogFields is a list of extra fields to log with every request.
type ExtraLogFields struct {
	fields []zapcore.Field
}

// Add adds a field to the list of extra fields to log.
func (e *ExtraLogFields) Add(field zap.Field) {
	e.fields = append(e.fields, field)
}

const (
	// Variable name used to indicate that this request
	// should be omitted from the access logs
	SkipLogVar string = "skip_log"

	// For adding additional fields to the access logs
	ExtraLogFieldsCtxKey caddy.CtxKey = "extra_log_fields"
)
