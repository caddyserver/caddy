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
			if strings.HasPrefix(key, queryReplPrefix) {
				vals := req.URL.Query()[key[len(queryReplPrefix):]]
				// always return true, since the query param might
				// be present only in some requests
				return strings.Join(vals, ","), true
			}

			if strings.HasPrefix(key, reqHeaderReplPrefix) {
				field := key[len(reqHeaderReplPrefix):]
				vals := req.Header[textproto.CanonicalMIMEHeaderKey(field)]
				// always return true, since the header field might
				// be present only in some requests
				return strings.Join(vals, ","), true
			}

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
			case "http.request.host":
				host, _, err := net.SplitHostPort(req.Host)
				if err != nil {
					return req.Host, true // OK; there probably was no port
				}
				return host, true
			case "http.request.hostport":
				return req.Host, true
			case "http.request.method":
				return req.Method, true
			case "http.request.port":
				_, port, _ := net.SplitHostPort(req.Host)
				return port, true
			case "http.request.scheme":
				if req.TLS != nil {
					return "https", true
				}
				return "http", true
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
			}

			if strings.HasPrefix(key, respHeaderReplPrefix) {
				field := key[len(respHeaderReplPrefix):]
				vals := w.Header()[textproto.CanonicalMIMEHeaderKey(field)]
				// always return true, since the header field might
				// be present only in some requests
				return strings.Join(vals, ","), true
			}

			if strings.HasPrefix(key, hostLabelReplPrefix) {
				idxStr := key[len(hostLabelReplPrefix):]
				idx, err := strconv.Atoi(idxStr)
				if err != nil {
					return "", false
				}
				hostLabels := strings.Split(req.Host, ".")
				if idx < 0 {
					return "", false
				}
				if idx >= len(hostLabels) {
					return "", true
				}
				return hostLabels[idx], true
			}

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
		}

		if w != nil {
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
	respHeaderReplPrefix = "http.response.header."
)
