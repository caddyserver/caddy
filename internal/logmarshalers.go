package internal

import (
	"net/http"
	"strings"

	"go.uber.org/zap/zapcore"
)

// LoggableHTTPHeader makes an HTTP header loggable with zap.Object().
// Headers with potentially sensitive information (Cookie, Set-Cookie,
// Authorization, and Proxy-Authorization) are logged with empty values.
type LoggableHTTPHeader struct {
	http.Header

	ShouldLogCredentials bool
}

// MarshalLogObject satisfies the zapcore.ObjectMarshaler interface.
func (h LoggableHTTPHeader) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	if h.Header == nil {
		return nil
	}
	for key, val := range h.Header {
		if !h.ShouldLogCredentials {
			switch strings.ToLower(key) {
			case "cookie", "set-cookie", "authorization", "proxy-authorization":
				val = []string{"REDACTED"} // see #5669. I still think ▒▒▒▒ would be cool.
			}
		}
		enc.AddArray(key, LoggableStringArray(val))
	}
	return nil
}

// LoggableStringArray makes a slice of strings marshalable for logging.
type LoggableStringArray []string

// MarshalLogArray satisfies the zapcore.ArrayMarshaler interface.
func (sa LoggableStringArray) MarshalLogArray(enc zapcore.ArrayEncoder) error {
	if sa == nil {
		return nil
	}
	for _, s := range sa {
		enc.AppendString(s)
	}
	return nil
}

// Interface guards
var (
	_ zapcore.ObjectMarshaler = (*LoggableHTTPHeader)(nil)
	_ zapcore.ArrayMarshaler  = (*LoggableStringArray)(nil)
)
