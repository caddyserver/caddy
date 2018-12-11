// Copyright 2015 Matthew Holt
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

package certmagic

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/xenolf/lego/challenge/http01"
)

// HTTPChallengeHandler wraps h in a handler that can solve the ACME
// HTTP challenge. cfg is required, and it must have a certificate
// cache backed by a functional storage facility, since that is where
// the challenge state is stored between initiation and solution.
//
// If a request is not an ACME HTTP challenge, h willl be invoked.
func (cfg *Config) HTTPChallengeHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cfg.HandleHTTPChallenge(w, r) {
			return
		}
		h.ServeHTTP(w, r)
	})
}

// HandleHTTPChallenge uses cfg to solve challenge requests from an ACME
// server that were initiated by this instance or any other instance in
// this cluster (being, any instances using the same storage cfg does).
//
// If the HTTP challenge is disabled, this function is a no-op.
//
// If cfg is nil or if cfg does not have a certificate cache backed by
// usable storage, solving the HTTP challenge will fail.
//
// It returns true if it handled the request; if so, the response has
// already been written. If false is returned, this call was a no-op and
// the request has not been handled.
func (cfg *Config) HandleHTTPChallenge(w http.ResponseWriter, r *http.Request) bool {
	if cfg == nil {
		return false
	}
	if cfg.DisableHTTPChallenge {
		return false
	}
	if !strings.HasPrefix(r.URL.Path, challengeBasePath) {
		return false
	}
	return cfg.distributedHTTPChallengeSolver(w, r)
}

// distributedHTTPChallengeSolver checks to see if this challenge
// request was initiated by this or another instance which uses the
// same storage as cfg does, and attempts to complete the challenge for
// it. It returns true if the request was handled; false otherwise.
func (cfg *Config) distributedHTTPChallengeSolver(w http.ResponseWriter, r *http.Request) bool {
	if cfg == nil {
		return false
	}

	tokenKey := distributedSolver{config: cfg}.challengeTokensKey(r.Host)
	chalInfoBytes, err := cfg.certCache.storage.Load(tokenKey)
	if err != nil {
		if _, ok := err.(ErrNotExist); !ok {
			log.Printf("[ERROR][%s] Opening distributed HTTP challenge token file: %v", r.Host, err)
		}
		return false
	}

	var chalInfo challengeInfo
	err = json.Unmarshal(chalInfoBytes, &chalInfo)
	if err != nil {
		log.Printf("[ERROR][%s] Decoding challenge token file %s (corrupted?): %v", r.Host, tokenKey, err)
		return false
	}

	return answerHTTPChallenge(w, r, chalInfo)
}

// answerHTTPChallenge solves the challenge with chalInfo.
// Most of this code borrowed from xenolf/lego's built-in HTTP-01
// challenge solver in March 2018.
func answerHTTPChallenge(w http.ResponseWriter, r *http.Request, chalInfo challengeInfo) bool {
	challengeReqPath := http01.ChallengePath(chalInfo.Token)
	if r.URL.Path == challengeReqPath &&
		strings.HasPrefix(r.Host, chalInfo.Domain) &&
		r.Method == "GET" {
		w.Header().Add("Content-Type", "text/plain")
		w.Write([]byte(chalInfo.KeyAuth))
		r.Close = true
		log.Printf("[INFO][%s] Served key authentication (distributed)", chalInfo.Domain)
		return true
	}
	return false
}

const challengeBasePath = "/.well-known/acme-challenge"
