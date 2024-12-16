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
	"crypto/x509"
	"fmt"
	"log"
	"runtime/debug"
	"time"

	"go.uber.org/zap"
)

func (p *PKI) maintenance() {
	defer func() {
		if err := recover(); err != nil {
			log.Printf("[PANIC] PKI maintenance: %v\n%s", err, debug.Stack())
		}
	}()

	ticker := time.NewTicker(10 * time.Minute) // TODO: make configurable
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.renewCerts()
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
	ca.mu.Lock()
	defer ca.mu.Unlock()

	log := p.log.With(zap.String("ca", ca.ID))

	// only maintain the root if it's not manually provided in the config
	if ca.Root == nil {
		if needsRenewal(ca.root) {
			// TODO: implement root renewal (use same key)
			log.Warn("root certificate expiring soon (FIXME: ROOT RENEWAL NOT YET IMPLEMENTED)",
				zap.Duration("time_remaining", time.Until(ca.inter.NotAfter)),
			)
		}
	}

	// only maintain the intermediate if it's not manually provided in the config
	if ca.Intermediate == nil {
		if needsRenewal(ca.inter) {
			log.Info("intermediate expires soon; renewing",
				zap.Duration("time_remaining", time.Until(ca.inter.NotAfter)),
			)

			rootCert, rootKey, err := ca.loadOrGenRoot()
			if err != nil {
				return fmt.Errorf("loading root key: %v", err)
			}
			interCert, interKey, err := ca.genIntermediate(rootCert, rootKey)
			if err != nil {
				return fmt.Errorf("generating new certificate: %v", err)
			}
			ca.inter, ca.interKey = interCert, interKey

			log.Info("renewed intermediate",
				zap.Time("new_expiration", ca.inter.NotAfter),
			)
		}
	}

	return nil
}

func needsRenewal(cert *x509.Certificate) bool {
	lifetime := cert.NotAfter.Sub(cert.NotBefore)
	renewalWindow := time.Duration(float64(lifetime) * renewalWindowRatio)
	renewalWindowStart := cert.NotAfter.Add(-renewalWindow)
	return time.Now().After(renewalWindowStart)
}

const renewalWindowRatio = 0.2 // TODO: make configurable
