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
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	"github.com/xenolf/lego/acme"
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

	// see if another instance started the HTTP challenge for this name
	if tryDistributedChallengeSolver(w, r) {
		return true
	}

	// otherwise, if we aren't getting the name, then ignore this challenge
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

// tryDistributedChallengeSolver checks to see if this challenge
// request was initiated by another instance that shares file
// storage, and attempts to complete the challenge for it. It
// returns true if the challenge was handled; false otherwise.
func tryDistributedChallengeSolver(w http.ResponseWriter, r *http.Request) bool {
	filePath := distributedHTTPSolver{}.challengeTokensPath(r.Host)
	f, err := os.Open(filePath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("[ERROR][%s] Opening distributed challenge token file: %v", r.Host, err)
		}
		return false
	}
	defer f.Close()

	var chalInfo challengeInfo
	err = json.NewDecoder(f).Decode(&chalInfo)
	if err != nil {
		log.Printf("[ERROR][%s] Decoding challenge token file %s (corrupted?): %v", r.Host, filePath, err)
		return false
	}

	// this part borrowed from xenolf/lego's built-in HTTP-01 challenge solver (March 2018)
	challengeReqPath := acme.HTTP01ChallengePath(chalInfo.Token)
	if r.URL.Path == challengeReqPath &&
		strings.HasPrefix(r.Host, chalInfo.Domain) &&
		r.Method == "GET" {
		w.Header().Add("Content-Type", "text/plain")
		w.Write([]byte(chalInfo.KeyAuth))
		r.Close = true
		log.Printf("[INFO][%s] Served key authentication", chalInfo.Domain)
		return true
	}

	return false
}
