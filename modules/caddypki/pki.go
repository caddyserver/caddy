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

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
)

func init() {
	caddy.RegisterModule(PKI{})
}

// PKI provides Public Key Infrastructure facilities for Caddy.
//
// This app can define certificate authorities (CAs) which are capable
// of signing certificates. Other modules can be configured to use
// the CAs defined by this app for issuing certificates or getting
// key information needed for establishing trust.
type PKI struct {
	// The certificate authorities to manage. Each CA is keyed by an
	// ID that is used to uniquely identify it from other CAs.
	// At runtime, the GetCA() method should be used instead to ensure
	// the default CA is provisioned if it hadn't already been.
	// The default CA ID is "local".
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
	p.log = ctx.Logger()

	for caID, ca := range p.CAs {
		err := ca.Provision(ctx, caID, p.log)
		if err != nil {
			return fmt.Errorf("provisioning CA '%s': %v", caID, err)
		}
	}

	// if this app is initialized at all, ensure there's at
	// least a default CA that can be used: the standard CA
	// which is used implicitly for signing local-use certs
	if len(p.CAs) == 0 {
		err := p.ProvisionDefaultCA(ctx)
		if err != nil {
			return fmt.Errorf("provisioning CA '%s': %v", DefaultCAID, err)
		}
	}

	return nil
}

// ProvisionDefaultCA sets up the default CA.
func (p *PKI) ProvisionDefaultCA(ctx caddy.Context) error {
	if p.CAs == nil {
		p.CAs = make(map[string]*CA)
	}

	p.CAs[DefaultCAID] = new(CA)
	return p.CAs[DefaultCAID].Provision(ctx, DefaultCAID, p.log)
}

// Start starts the PKI app.
func (p *PKI) Start() error {
	// install roots to trust store, if not disabled
	for _, ca := range p.CAs {
		if ca.InstallTrust != nil && !*ca.InstallTrust {
			ca.log.Info("root certificate trust store installation disabled; unconfigured clients may show warnings",
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

// GetCA retrieves a CA by ID. If the ID is the default
// CA ID, and it hasn't been provisioned yet, it will
// be provisioned.
func (p *PKI) GetCA(ctx caddy.Context, id string) (*CA, error) {
	ca, ok := p.CAs[id]
	if !ok {
		// for anything other than the default CA ID, error out if it wasn't configured
		if id != DefaultCAID {
			return nil, fmt.Errorf("no certificate authority configured with id: %s", id)
		}

		// for the default CA ID, provision it, because we want it to "just work"
		err := p.ProvisionDefaultCA(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to provision default CA: %s", err)
		}
		ca = p.CAs[id]
	}

	return ca, nil
}

// Interface guards
var (
	_ caddy.Provisioner = (*PKI)(nil)
	_ caddy.App         = (*PKI)(nil)
)
