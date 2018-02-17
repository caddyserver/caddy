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

package caddytls

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

const challengeBasePath = "/.well-known/acme-challenge"

// HTTPChallengeHandler proxies challenge requests to ACME client if the
// request path starts with challengeBasePath, if the HTTP challenge is not
// disabled, and if we are known to be obtaining a certificate for the name.
// It returns true if it handled the request and no more needs to be done;
// it returns false if this call was a no-op and the request still needs handling.
func HTTPChallengeHandler(w http.ResponseWriter, r *http.Request, listenHost string) bool {
	if !strings.HasPrefix(r.URL.Path, challengeBasePath) {
		return false
	}
	if DisableHTTPChallenge {
		return false
	}
	if !namesObtaining.Has(r.Host) {
		return false
	}

	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}

	if listenHost == "" {
		listenHost = "localhost"
	}

	// always proxy to the DefaultHTTPAlternatePort because obviously the
	// ACME challenge request already got into one of our HTTP handlers, so
	// it means we must have started a HTTP listener on the alternate
	// port instead; which is only accessible via listenHost
	upstream, err := url.Parse(fmt.Sprintf("%s://%s:%s", scheme, listenHost, DefaultHTTPAlternatePort))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("[ERROR] ACME proxy handler: %v", err)
		return true
	}

	proxy := httputil.NewSingleHostReverseProxy(upstream)
	proxy.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	proxy.ServeHTTP(w, r)

	return true
}
