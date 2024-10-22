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
	"crypto/tls"
	"net"
	"net/http"
	"strings"

	"go.uber.org/zap/zapcore"
)

// LoggableHTTPRequest makes an HTTP request loggable with zap.Object().
type LoggableHTTPRequest struct {
	*http.Request

	ShouldLogCredentials bool
}

// MarshalLogObject satisfies the zapcore.ObjectMarshaler interface.
func (r LoggableHTTPRequest) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	ip, port, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
		port = ""
	}

	enc.AddString("remote_ip", ip)
	enc.AddString("remote_port", port)
	if ip, ok := GetVar(r.Context(), ClientIPVarKey).(string); ok {
		enc.AddString("client_ip", ip)
	}
	enc.AddString("proto", r.Proto)
	enc.AddString("method", r.Method)
	enc.AddString("host", r.Host)
	enc.AddString("uri", r.RequestURI)
	enc.AddObject("headers", LoggableHTTPHeader{
		Header:               r.Header,
		ShouldLogCredentials: r.ShouldLogCredentials,
	})
	if r.TransferEncoding != nil {
		enc.AddArray("transfer_encoding", LoggableStringArray(r.TransferEncoding))
	}
	if r.TLS != nil {
		enc.AddObject("tls", LoggableTLSConnState(*r.TLS))
	}
	return nil
}

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

// LoggableTLSConnState makes a TLS connection state loggable with zap.Object().
type LoggableTLSConnState tls.ConnectionState

// MarshalLogObject satisfies the zapcore.ObjectMarshaler interface.
func (t LoggableTLSConnState) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddBool("resumed", t.DidResume)
	enc.AddUint16("version", t.Version)
	enc.AddUint16("cipher_suite", t.CipherSuite)
	enc.AddString("proto", t.NegotiatedProtocol)
	enc.AddString("server_name", t.ServerName)
	if len(t.PeerCertificates) > 0 {
		enc.AddString("client_common_name", t.PeerCertificates[0].Subject.CommonName)
		enc.AddString("client_serial", t.PeerCertificates[0].SerialNumber.String())
	}
	return nil
}

// Interface guards
var (
	_ zapcore.ObjectMarshaler = (*LoggableHTTPRequest)(nil)
	_ zapcore.ObjectMarshaler = (*LoggableHTTPHeader)(nil)
	_ zapcore.ArrayMarshaler  = (*LoggableStringArray)(nil)
	_ zapcore.ObjectMarshaler = (*LoggableTLSConnState)(nil)
)
