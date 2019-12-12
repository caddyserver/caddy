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
	"fmt"
	"net"
	"net/http"
	"net/textproto"
	"path"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2"
)

func addHTTPVarsToReplacer(repl caddy.Replacer, req *http.Request, w http.ResponseWriter) {
	httpVars := func(key string) (string, bool) {
		if req != nil {
			// query string parameters
			if strings.HasPrefix(key, queryReplPrefix) {
				vals := req.URL.Query()[key[len(queryReplPrefix):]]
				// always return true, since the query param might
				// be present only in some requests
				return strings.Join(vals, ","), true
			}

			// request header fields
			if strings.HasPrefix(key, reqHeaderReplPrefix) {
				field := key[len(reqHeaderReplPrefix):]
				vals := req.Header[textproto.CanonicalMIMEHeaderKey(field)]
				// always return true, since the header field might
				// be present only in some requests
				return strings.Join(vals, ","), true
			}

			// cookies
			if strings.HasPrefix(key, cookieReplPrefix) {
				name := key[len(cookieReplPrefix):]
				for _, cookie := range req.Cookies() {
					if strings.EqualFold(name, cookie.Name) {
						// always return true, since the cookie might
						// be present only in some requests
						return cookie.Value, true
					}
				}
			}

			switch key {
			case "http.request.method":
				return req.Method, true
			case "http.request.scheme":
				if req.TLS != nil {
					return "https", true
				}
				return "http", true
			case "http.request.proto":
				return req.Proto, true
			case "http.request.host":
				host, _, err := net.SplitHostPort(req.Host)
				if err != nil {
					return req.Host, true // OK; there probably was no port
				}
				return host, true
			case "http.request.port":
				_, port, _ := net.SplitHostPort(req.Host)
				return port, true
			case "http.request.hostport":
				return req.Host, true
			case "http.request.remote":
				return req.RemoteAddr, true
			case "http.request.remote.host":
				host, _, err := net.SplitHostPort(req.RemoteAddr)
				if err != nil {
					return req.RemoteAddr, true
				}
				return host, true
			case "http.request.remote.port":
				_, port, _ := net.SplitHostPort(req.RemoteAddr)
				return port, true

			// current URI, including any internal rewrites
			case "http.request.uri":
				return req.URL.RequestURI(), true
			case "http.request.uri.path":
				return req.URL.Path, true
			case "http.request.uri.path.file":
				_, file := path.Split(req.URL.Path)
				return file, true
			case "http.request.uri.path.dir":
				dir, _ := path.Split(req.URL.Path)
				return dir, true
			case "http.request.uri.query":
				return req.URL.RawQuery, true
			case "http.request.uri.query_string":
				return "?" + req.URL.Query().Encode(), true

				// original request, before any internal changes
			case "http.request.orig_method":
				or, _ := req.Context().Value(OriginalRequestCtxKey).(http.Request)
				return or.Method, true
			case "http.request.orig_uri":
				or, _ := req.Context().Value(OriginalRequestCtxKey).(http.Request)
				return or.RequestURI, true
			case "http.request.orig_uri.path":
				or, _ := req.Context().Value(OriginalRequestCtxKey).(http.Request)
				return or.URL.Path, true
			case "http.request.orig_uri.path.file":
				or, _ := req.Context().Value(OriginalRequestCtxKey).(http.Request)
				_, file := path.Split(or.URL.Path)
				return file, true
			case "http.request.orig_uri.path.dir":
				or, _ := req.Context().Value(OriginalRequestCtxKey).(http.Request)
				dir, _ := path.Split(or.URL.Path)
				return dir, true
			case "http.request.orig_uri.query":
				or, _ := req.Context().Value(OriginalRequestCtxKey).(http.Request)
				return or.URL.RawQuery, true
			case "http.request.orig_uri.query_string":
				or, _ := req.Context().Value(OriginalRequestCtxKey).(http.Request)
				qs := or.URL.Query().Encode()
				if qs != "" {
					qs = "?" + qs
				}
				return qs, true
			}

			// hostname labels
			if strings.HasPrefix(key, hostLabelReplPrefix) {
				idxStr := key[len(hostLabelReplPrefix):]
				idx, err := strconv.Atoi(idxStr)
				if err != nil {
					return "", false
				}
				reqHost, _, err := net.SplitHostPort(req.Host)
				if err != nil {
					reqHost = req.Host // OK; assume there was no port
				}
				hostLabels := strings.Split(reqHost, ".")
				if idx < 0 {
					return "", false
				}
				if idx > len(hostLabels) {
					return "", true
				}
				return hostLabels[len(hostLabels)-idx-1], true
			}

			// path parts
			if strings.HasPrefix(key, pathPartsReplPrefix) {
				idxStr := key[len(pathPartsReplPrefix):]
				idx, err := strconv.Atoi(idxStr)
				if err != nil {
					return "", false
				}
				pathParts := strings.Split(req.URL.Path, "/")
				if len(pathParts) > 0 && pathParts[0] == "" {
					pathParts = pathParts[1:]
				}
				if idx < 0 {
					return "", false
				}
				if idx >= len(pathParts) {
					return "", true
				}
				return pathParts[idx], true
			}

			// middleware variables
			if strings.HasPrefix(key, varsReplPrefix) {
				varName := key[len(varsReplPrefix):]
				tbl := req.Context().Value(VarsCtxKey).(map[string]interface{})
				raw, ok := tbl[varName]
				if !ok {
					// variables can be dynamic, so always return true
					// even when it may not be set; treat as empty
					return "", true
				}
				// do our best to convert it to a string efficiently
				switch val := raw.(type) {
				case string:
					return val, true
				case fmt.Stringer:
					return val.String(), true
				default:
					return fmt.Sprintf("%s", val), true
				}
			}
		}

		if w != nil {
			// response header fields
			if strings.HasPrefix(key, respHeaderReplPrefix) {
				field := key[len(respHeaderReplPrefix):]
				vals := w.Header()[textproto.CanonicalMIMEHeaderKey(field)]
				// always return true, since the header field might
				// be present only in some responses
				return strings.Join(vals, ","), true
			}
		}

		return "", false
	}

	repl.Map(httpVars)
}

const (
	queryReplPrefix      = "http.request.uri.query."
	reqHeaderReplPrefix  = "http.request.header."
	cookieReplPrefix     = "http.request.cookie."
	hostLabelReplPrefix  = "http.request.host.labels."
	pathPartsReplPrefix  = "http.request.uri.path."
	varsReplPrefix       = "http.vars."
	respHeaderReplPrefix = "http.response.header."
)
