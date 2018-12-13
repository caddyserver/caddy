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
	"fmt"
	"sync"
	"time"
)

// Cache is a structure that stores certificates in memory.
// Generally, there should only be one per process. However,
// complex applications that virtualize the concept of a
// "process" (such as Caddy, which virtualizes processes as
// "instances" so it can do graceful, in-memory reloads of
// its configuration) may use more of these per OS process.
//
// Using just one cache per process avoids duplication of
// certificates across multiple configurations and makes
// maintenance easier.
//
// An empty cache is INVALID and must not be used.
// Be sure to call NewCertificateCache to get one.
//
// These should be very long-lived values, and must not be
// copied. Before all references leave scope to be garbage
// collected, ensure you call Stop() to stop maintenance
// maintenance on the certificates stored in this cache.
type Cache struct {
	// How often to check certificates for renewal
	RenewInterval time.Duration

	// How often to check if OCSP stapling needs updating
	OCSPInterval time.Duration

	// The storage implementation
	storage Storage

	// The cache is keyed by certificate hash
	cache map[string]Certificate

	// Protects the cache map
	mu sync.RWMutex

	// Close this channel to cancel asset maintenance
	stopChan chan struct{}
}

// NewCache returns a new, valid Cache backed by the
// given storage implementation. It also begins a
// maintenance goroutine for any managed certificates
// stored in this cache.
//
// See the godoc for Cache to use it properly.
//
// Note that all processes running in a cluster
// configuration must use the same storage value
// in order to share certificates. (A single storage
// value may be shared by multiple clusters as well.)
func NewCache(storage Storage) *Cache {
	c := &Cache{
		RenewInterval: DefaultRenewInterval,
		OCSPInterval:  DefaultOCSPInterval,
		storage:       storage,
		cache:         make(map[string]Certificate),
		stopChan:      make(chan struct{}),
	}
	go c.maintainAssets()
	return c
}

// Stop stops the maintenance goroutine for
// certificates in certCache.
func (certCache *Cache) Stop() {
	close(certCache.stopChan)
}

// replaceCertificate replaces oldCert with newCert in the cache, and
// updates all configs that are pointing to the old certificate to
// point to the new one instead. newCert must already be loaded into
// the cache (this method does NOT load it into the cache).
//
// Note that all the names on the old certificate will be deleted
// from the name lookup maps of each config, then all the names on
// the new certificate will be added to the lookup maps as long as
// they do not overwrite any entries.
//
// The newCert may be modified and its cache entry updated.
//
// This method is safe for concurrent use.
func (certCache *Cache) replaceCertificate(oldCert, newCert Certificate) error {
	certCache.mu.Lock()
	defer certCache.mu.Unlock()

	// have all the configs that are pointing to the old
	// certificate point to the new certificate instead
	for _, cfg := range oldCert.configs {
		// first delete all the name lookup entries that
		// pointed to the old certificate
		for name, certKey := range cfg.certificates {
			if certKey == oldCert.Hash {
				delete(cfg.certificates, name)
			}
		}

		// then add name lookup entries for the names
		// on the new certificate, but don't overwrite
		// entries that may already exist, not only as
		// a courtesy, but importantly: because if we
		// overwrote a value here, and this config no
		// longer pointed to a certain certificate in
		// the cache, that certificate's list of configs
		// referring to it would be incorrect; so just
		// insert entries, don't overwrite any
		for _, name := range newCert.Names {
			if _, ok := cfg.certificates[name]; !ok {
				cfg.certificates[name] = newCert.Hash
			}
		}
	}

	// since caching a new certificate attaches only the config
	// that loaded it, the new certificate needs to be given the
	// list of all the configs that use it, so copy the list
	// over from the old certificate to the new certificate
	// in the cache
	newCert.configs = oldCert.configs
	certCache.cache[newCert.Hash] = newCert

	// finally, delete the old certificate from the cache
	delete(certCache.cache, oldCert.Hash)

	return nil
}

// reloadManagedCertificate reloads the certificate corresponding to the name(s)
// on oldCert into the cache, from storage. This also replaces the old certificate
// with the new one, so that all configurations that used the old cert now point
// to the new cert.
func (certCache *Cache) reloadManagedCertificate(oldCert Certificate) error {
	// get the certificate from storage and cache it
	newCert, err := oldCert.configs[0].CacheManagedCertificate(oldCert.Names[0])
	if err != nil {
		return fmt.Errorf("unable to reload certificate for %v into cache: %v", oldCert.Names, err)
	}

	// and replace the old certificate with the new one
	err = certCache.replaceCertificate(oldCert, newCert)
	if err != nil {
		return fmt.Errorf("replacing certificate %v: %v", oldCert.Names, err)
	}

	return nil
}

var defaultCache *Cache
var defaultCacheMu sync.Mutex
