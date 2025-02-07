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
	"encoding/json"
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
	// hostnames that are not in the logger_names map.
	DefaultLoggerName string `json:"default_logger_name,omitempty"`

	// LoggerNames maps request hostnames to one or more custom logger
	// names. For example, a mapping of `"example.com": ["example"]` would
	// cause access logs from requests with a Host of example.com to be
	// emitted by a logger named "http.log.access.example". If there are
	// multiple logger names, then the log will be emitted to all of them.
	// If the logger name is an empty, the default logger is used, i.e.
	// the logger "http.log.access".
	//
	// Keys must be hostnames (without ports), and may contain wildcards
	// to match subdomains. The value is an array of logger names.
	//
	// For backwards compatibility, if the value is a string, it is treated
	// as a single-element array.
	LoggerNames map[string]StringArray `json:"logger_names,omitempty"`

	// By default, all requests to this server will be logged if
	// access logging is enabled. This field lists the request
	// hosts for which access logging should be disabled.
	SkipHosts []string `json:"skip_hosts,omitempty"`

	// If true, requests to any host not appearing in the
	// logger_names map will not be logged.
	SkipUnmappedHosts bool `json:"skip_unmapped_hosts,omitempty"`

	// If true, credentials that are otherwise omitted, will be logged.
	// The definition of credentials is defined by https://fetch.spec.whatwg.org/#credentials,
	// and this includes some request and response headers, i.e `Cookie`,
	// `Set-Cookie`, `Authorization`, and `Proxy-Authorization`.
	ShouldLogCredentials bool `json:"should_log_credentials,omitempty"`

	// Log each individual handler that is invoked.
	// Requires that the log emit at DEBUG level.
	//
	// NOTE: This may log the configuration of your
	// HTTP handler modules; do not enable this in
	// insecure contexts when there is sensitive
	// data in the configuration.
	//
	// EXPERIMENTAL: Subject to change or removal.
	Trace bool `json:"trace,omitempty"`
}

// wrapLogger wraps logger in one or more logger named
// according to user preferences for the given host.
func (slc ServerLogConfig) wrapLogger(logger *zap.Logger, req *http.Request) []*zap.Logger {
	// using the `log_name` directive or the `access_logger_names` variable,
	// the logger names can be overridden for the current request
	if names := GetVar(req.Context(), AccessLoggerNameVarKey); names != nil {
		if namesSlice, ok := names.([]any); ok {
			loggers := make([]*zap.Logger, 0, len(namesSlice))
			for _, loggerName := range namesSlice {
				// no name, use the default logger
				if loggerName == "" {
					loggers = append(loggers, logger)
					continue
				}
				// make a logger with the given name
				loggers = append(loggers, logger.Named(loggerName.(string)))
			}
			return loggers
		}
	}

	// get the hostname from the request, with the port number stripped
	host, _, err := net.SplitHostPort(req.Host)
	if err != nil {
		host = req.Host
	}

	// get the logger names for this host from the config
	hosts := slc.getLoggerHosts(host)

	// make a list of named loggers, or the default logger
	loggers := make([]*zap.Logger, 0, len(hosts))
	for _, loggerName := range hosts {
		// no name, use the default logger
		if loggerName == "" {
			loggers = append(loggers, logger)
			continue
		}
		// make a logger with the given name
		loggers = append(loggers, logger.Named(loggerName))
	}
	return loggers
}

func (slc ServerLogConfig) getLoggerHosts(host string) []string {
	// try the exact hostname first
	if hosts, ok := slc.LoggerNames[host]; ok {
		return hosts
	}

	// try matching wildcard domains if other non-specific loggers exist
	labels := strings.Split(host, ".")
	for i := range labels {
		if labels[i] == "" {
			continue
		}
		labels[i] = "*"
		wildcardHost := strings.Join(labels, ".")
		if hosts, ok := slc.LoggerNames[wildcardHost]; ok {
			return hosts
		}
	}

	return []string{slc.DefaultLoggerName}
}

func (slc *ServerLogConfig) clone() *ServerLogConfig {
	clone := &ServerLogConfig{
		DefaultLoggerName:    slc.DefaultLoggerName,
		LoggerNames:          make(map[string]StringArray),
		SkipHosts:            append([]string{}, slc.SkipHosts...),
		SkipUnmappedHosts:    slc.SkipUnmappedHosts,
		ShouldLogCredentials: slc.ShouldLogCredentials,
	}
	for k, v := range slc.LoggerNames {
		clone.LoggerNames[k] = append([]string{}, v...)
	}
	return clone
}

// StringArray is a slices of strings, but also accepts
// a single string as a value when JSON unmarshaling,
// converting it to a slice of one string.
type StringArray []string

// UnmarshalJSON satisfies json.Unmarshaler.
func (sa *StringArray) UnmarshalJSON(b []byte) error {
	var jsonObj any
	err := json.Unmarshal(b, &jsonObj)
	if err != nil {
		return err
	}
	switch obj := jsonObj.(type) {
	case string:
		*sa = StringArray([]string{obj})
		return nil
	case []any:
		s := make([]string, 0, len(obj))
		for _, v := range obj {
			value, ok := v.(string)
			if !ok {
				return errors.New("unsupported type")
			}
			s = append(s, value)
		}
		*sa = StringArray(s)
		return nil
	}
	return errors.New("unsupported type")
}

// errLogValues inspects err and returns the status code
// to use, the error log message, and any extra fields.
// If err is a HandlerError, the returned values will
// have richer information.
func errLogValues(err error) (status int, msg string, fields func() []zapcore.Field) {
	var handlerErr HandlerError
	if errors.As(err, &handlerErr) {
		status = handlerErr.StatusCode
		if handlerErr.Err == nil {
			msg = err.Error()
		} else {
			msg = handlerErr.Err.Error()
		}
		fields = func() []zapcore.Field {
			return []zapcore.Field{
				zap.Int("status", handlerErr.StatusCode),
				zap.String("err_id", handlerErr.ID),
				zap.String("err_trace", handlerErr.Trace),
			}
		}
		return
	}
	fields = func() []zapcore.Field {
		return []zapcore.Field{
			zap.Error(err),
		}
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

// Set sets a field in the list of extra fields to log.
// If the field already exists, it is replaced.
func (e *ExtraLogFields) Set(field zap.Field) {
	for i := range e.fields {
		if e.fields[i].Key == field.Key {
			e.fields[i] = field
			return
		}
	}
	e.fields = append(e.fields, field)
}

const (
	// Variable name used to indicate that this request
	// should be omitted from the access logs
	LogSkipVar string = "log_skip"

	// For adding additional fields to the access logs
	ExtraLogFieldsCtxKey caddy.CtxKey = "extra_log_fields"

	// Variable name used to indicate the logger to be used
	AccessLoggerNameVarKey string = "access_logger_names"
)
