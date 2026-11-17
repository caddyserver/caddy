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

package caddypki

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"runtime/debug"
	"time"

	"go.uber.org/zap"
)

func (p *PKI) maintenanceForCA(ca *CA) {
	defer func() {
		if err := recover(); err != nil {
			log.Printf("[PANIC] PKI maintenance for CA %s: %v\n%s", ca.ID, err, debug.Stack())
		}
	}()

	interval := time.Duration(ca.MaintenanceInterval)
	if interval <= 0 {
		interval = defaultMaintenanceInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			_ = p.renewCertsForCA(ca)
		case <-p.ctx.Done():
			return
		}
	}
}

func (p *PKI) renewCerts() {
	for _, ca := range p.CAs {
		err := p.renewCertsForCA(ca)
		if err != nil {
			p.log.Error("renewing intermediate certificates",
				zap.Error(err),
				zap.String("ca", ca.ID))
		}
	}
}

func (p *PKI) renewCertsForCA(ca *CA) error {
	ca.mu.RLock()
	rootCert, interCert := ca.root, ca.interChain[0]
	ca.mu.RUnlock()

	log := p.log.With(zap.String("ca", ca.ID))

	// only maintain the root if it's not manually provided in the config
	if ca.Root == nil {
		if ca.needsRenewal(rootCert) {
			// TODO: implement root renewal (use same key)
			log.Warn("root certificate expiring soon (FIXME: ROOT RENEWAL NOT YET IMPLEMENTED)",
				zap.Duration("time_remaining", time.Until(rootCert.NotAfter)),
			)
		}
	}

	// only maintain the intermediate if it's not manually provided in the config
	if ca.Intermediate == nil {
		if ca.needsRenewal(interCert) {
			log.Info("intermediate expires soon; renewing",
				zap.Duration("time_remaining", time.Until(interCert.NotAfter)),
			)

			// Instances sharing this storage all reach the renewal window at about
			// the same time: renew under the storage lock, and adopt the intermediate
			// another instance stored while we were waiting for it, if any.
			var (
				interChain []*x509.Certificate
				interKey   crypto.Signer
				renewed    bool
			)
			err := ca.withStorageLock(func() error {
				rootCert, rootKey, err := ca.loadOrGenRootLocked()
				if err != nil {
					return fmt.Errorf("loading root key: %v", err)
				}
				chain, key, err := ca.loadIntermediate(rootCert)
				if err == nil && !ca.needsRenewal(chain[0]) {
					interChain, interKey = chain, key
					return nil
				}
				if err != nil && !errors.Is(err, fs.ErrNotExist) {
					log.Error("intermediate in storage is unusable; replacing it", zap.Error(err))
				}
				newCert, newKey, err := ca.genIntermediate(rootCert, rootKey)
				if err != nil {
					return fmt.Errorf("generating new certificate: %v", err)
				}
				interChain, interKey, renewed = []*x509.Certificate{newCert}, newKey, true
				return nil
			})
			if err != nil {
				return err
			}

			ca.mu.Lock()
			ca.interChain, ca.interKey = interChain, interKey
			ca.mu.Unlock()

			if renewed {
				log.Info("renewed intermediate",
					zap.Time("new_expiration", interChain[0].NotAfter),
				)
			} else {
				log.Info("loaded intermediate renewed by another instance",
					zap.Time("new_expiration", interChain[0].NotAfter),
				)
			}
		}
	}

	return nil
}

// needsRenewal reports whether the certificate is within its renewal window
// (i.e. the fraction of lifetime remaining is less than or equal to RenewalWindowRatio).
func (ca *CA) needsRenewal(cert *x509.Certificate) bool {
	ratio := ca.RenewalWindowRatio
	if ratio <= 0 {
		ratio = defaultRenewalWindowRatio
	}
	lifetime := cert.NotAfter.Sub(cert.NotBefore)
	renewalWindow := time.Duration(float64(lifetime) * ratio)
	renewalWindowStart := cert.NotAfter.Add(-renewalWindow)
	return time.Now().After(renewalWindowStart)
}
