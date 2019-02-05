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
	"fmt"
	"log"
	"path/filepath"

	"github.com/xenolf/lego/challenge"
	"github.com/xenolf/lego/challenge/tlsalpn01"
)

// tlsALPNSolver is a type that can solve TLS-ALPN challenges using
// an existing listener and our custom, in-memory certificate cache.
type tlsALPNSolver struct {
	certCache *Cache
}

// Present adds the challenge certificate to the cache.
func (s tlsALPNSolver) Present(domain, token, keyAuth string) error {
	cert, err := tlsalpn01.ChallengeCert(domain, keyAuth)
	if err != nil {
		return err
	}
	certHash := hashCertificateChain(cert.Certificate)
	s.certCache.mu.Lock()
	s.certCache.cache[tlsALPNCertKeyName(domain)] = Certificate{
		Certificate: *cert,
		Names:       []string{domain},
		Hash:        certHash, // perhaps not necesssary
	}
	s.certCache.mu.Unlock()
	return nil
}

// CleanUp removes the challenge certificate from the cache.
func (s tlsALPNSolver) CleanUp(domain, token, keyAuth string) error {
	s.certCache.mu.Lock()
	delete(s.certCache.cache, tlsALPNCertKeyName(domain))
	s.certCache.mu.Unlock()
	return nil
}

// tlsALPNCertKeyName returns the key to use when caching a cert
// for use with the TLS-ALPN ACME challenge. It is simply to help
// avoid conflicts (although at time of writing, there shouldn't
// be, since the cert cache is keyed by hash of certificate chain).
func tlsALPNCertKeyName(sniName string) string {
	return sniName + ":acme-tls-alpn"
}

// distributedSolver allows the ACME HTTP-01 and TLS-ALPN challenges
// to be solved by an instance other than the one which initiated it.
// This is useful behind load balancers or in other cluster/fleet
// configurations. The only requirement is that the instance which
// initiates the challenge shares the same storage and locker with
// the others in the cluster. The storage backing the certificate
// cache in distributedSolver.config is crucial.
//
// Obviously, the instance which completes the challenge must be
// serving on the HTTPChallengePort for the HTTP-01 challenge or the
// TLSALPNChallengePort for the TLS-ALPN-01 challenge (or have all
// the packets port-forwarded) to receive and handle the request. The
// server which receives the challenge must handle it by checking to
// see if the challenge token exists in storage, and if so, decode it
// and use it to serve up the correct response. HTTPChallengeHandler
// in this package as well as the GetCertificate method implemented
// by a Config support and even require this behavior.
//
// In short: the only two requirements for cluster operation are
// sharing sync and storage, and using the facilities provided by
// this package for solving the challenges.
type distributedSolver struct {
	// The config with a certificate cache
	// with a reference to the storage to
	// use which is shared among all the
	// instances in the cluster - REQUIRED.
	config *Config

	// Since the distributedSolver is only a
	// wrapper over an actual solver, place
	// the actual solver here.
	providerServer challenge.Provider
}

// Present invokes the underlying solver's Present method
// and also stores domain, token, and keyAuth to the storage
// backing the certificate cache of dhs.config.
func (dhs distributedSolver) Present(domain, token, keyAuth string) error {
	if dhs.providerServer != nil {
		err := dhs.providerServer.Present(domain, token, keyAuth)
		if err != nil {
			return fmt.Errorf("presenting with standard provider server: %v", err)
		}
	}

	infoBytes, err := json.Marshal(challengeInfo{
		Domain:  domain,
		Token:   token,
		KeyAuth: keyAuth,
	})
	if err != nil {
		return err
	}

	return dhs.config.certCache.storage.Store(dhs.challengeTokensKey(domain), infoBytes)
}

// CleanUp invokes the underlying solver's CleanUp method
// and also cleans up any assets saved to storage.
func (dhs distributedSolver) CleanUp(domain, token, keyAuth string) error {
	if dhs.providerServer != nil {
		err := dhs.providerServer.CleanUp(domain, token, keyAuth)
		if err != nil {
			log.Printf("[ERROR] Cleaning up standard provider server: %v", err)
		}
	}
	return dhs.config.certCache.storage.Delete(dhs.challengeTokensKey(domain))
}

// challengeTokensPrefix returns the key prefix for challenge info.
func (dhs distributedSolver) challengeTokensPrefix() string {
	return filepath.Join(StorageKeys.CAPrefix(dhs.config.CA), "challenge_tokens")
}

// challengeTokensKey returns the key to use to store and access
// challenge info for domain.
func (dhs distributedSolver) challengeTokensKey(domain string) string {
	return filepath.Join(dhs.challengeTokensPrefix(), StorageKeys.Safe(domain)+".json")
}

type challengeInfo struct {
	Domain, Token, KeyAuth string
}
