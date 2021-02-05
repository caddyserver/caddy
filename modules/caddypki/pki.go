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
	"fmt"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(PKI{})
}

// PKI provides Public Key Infrastructure facilities for Caddy.
type PKI struct {
	// The CAs to manage. Each CA is keyed by an ID that is used
	// to uniquely identify it from other CAs. The default CA ID
	// is "local".
	CAs map[string]*CA `json:"certificate_authorities,omitempty"`

	ctx caddy.Context
	log *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (PKI) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "pki",
		New: func() caddy.Module { return new(PKI) },
	}
}

// Provision sets up the configuration for the PKI app.
func (p *PKI) Provision(ctx caddy.Context) error {
	p.ctx = ctx
	p.log = ctx.Logger(p)

	// if this app is initialized at all, ensure there's at
	// least a default CA that can be used: the standard CA
	// which is used implicitly for signing local-use certs
	if p.CAs == nil {
		p.CAs = make(map[string]*CA)
	}
	if _, ok := p.CAs[DefaultCAID]; !ok {
		p.CAs[DefaultCAID] = new(CA)
	}

	for caID, ca := range p.CAs {
		err := ca.Provision(ctx, caID, p.log)
		if err != nil {
			return fmt.Errorf("provisioning CA '%s': %v", caID, err)
		}
	}

	return nil
}

// Start starts the PKI app.
func (p *PKI) Start() error {
	// install roots to trust store, if not disabled
	for _, ca := range p.CAs {
		if ca.InstallTrust != nil && !*ca.InstallTrust {
			ca.log.Warn("root certificate trust store installation disabled; unconfigured clients may show warnings",
				zap.String("path", ca.rootCertPath))
			continue
		}

		if err := ca.installRoot(); err != nil {
			// could be some system dependencies that are missing;
			// shouldn't totally prevent startup, but we should log it
			ca.log.Error("failed to install root certificate",
				zap.Error(err),
				zap.String("certificate_file", ca.rootCertPath))
		}
	}

	// see if root/intermediates need renewal...
	p.renewCerts()

	// ...and keep them renewed
	go p.maintenance()

	return nil
}

// Stop stops the PKI app.
func (p *PKI) Stop() error {
	return nil
}

// Interface guards
var (
	_ caddy.Provisioner = (*PKI)(nil)
	_ caddy.App         = (*PKI)(nil)
)
