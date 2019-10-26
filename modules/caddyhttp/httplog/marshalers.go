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
	"crypto/tls"
	"net/http"

	"go.uber.org/zap/zapcore"
)

// LoggableHTTPRequest makes an HTTP request loggable with zap.Object().
type LoggableHTTPRequest http.Request

// MarshalLogObject satisfies the zapcore.ObjectMarshaler interface.
func (r LoggableHTTPRequest) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("method", r.Method)
	enc.AddString("uri", r.RequestURI)
	enc.AddString("proto", r.Proto)
	enc.AddString("remote_addr", r.RemoteAddr)
	enc.AddString("host", r.Host)
	enc.AddObject("headers", LoggableHTTPHeader(r.Header))
	if r.TLS != nil {
		enc.AddObject("tls", LoggableTLSConnState(*r.TLS))
	}
	return nil
}

// LoggableHTTPHeader makes an HTTP header loggable with zap.Object().
type LoggableHTTPHeader http.Header

// MarshalLogObject satisfies the zapcore.ObjectMarshaler interface.
func (h LoggableHTTPHeader) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	if h == nil {
		return nil
	}
	for key, val := range h {
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

// LoggableTLSConnState makes a TLS connection state loggable with zap.Object().
type LoggableTLSConnState tls.ConnectionState

// MarshalLogObject satisfies the zapcore.ObjectMarshaler interface.
func (t LoggableTLSConnState) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddBool("resumed", t.DidResume)
	enc.AddUint16("version", t.Version)
	enc.AddUint16("resumed", t.CipherSuite)
	enc.AddString("proto", t.NegotiatedProtocol)
	enc.AddBool("proto_mutual", t.NegotiatedProtocolIsMutual)
	enc.AddString("server_name", t.ServerName)
	return nil
}

// Interface guards
var (
	_ zapcore.ObjectMarshaler = (*LoggableHTTPRequest)(nil)
	_ zapcore.ObjectMarshaler = (*LoggableHTTPHeader)(nil)
	_ zapcore.ArrayMarshaler  = (*LoggableStringArray)(nil)
	_ zapcore.ObjectMarshaler = (*LoggableTLSConnState)(nil)
)
