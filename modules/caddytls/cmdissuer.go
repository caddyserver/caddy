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

package caddytls

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os/exec"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(CommandIssuer{})
}

// CommandIssuer issues certificates by invoking a shell command.
// The command will receive the base64-encoded ASN.1 DER encoding of the CSR via its stdin.
// The command must output the PEM-encoded certificate (chain) to stdout.
type CommandIssuer struct {
	// The command to execute.
	Command string `json:"cmd"`

	// Arguments to the command.
	Args []string `json:"args,omitempty"`

	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (CommandIssuer) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.issuance.cmd",
		New: func() caddy.Module { return new(CommandIssuer) },
	}
}

// Provision sets up iss.
func (iss *CommandIssuer) Provision(ctx caddy.Context) error {
	iss.logger = ctx.Logger(iss)
	return nil
}

// IssuerKey returns the unique issuer key for the configured CA endpoint.
func (iss *CommandIssuer) IssuerKey() string { return "cmd" }

// Issue obtains a certificate for the given csr.
func (iss *CommandIssuer) Issue(ctx context.Context, csr *x509.CertificateRequest) (*certmagic.IssuedCertificate, error) {
	b64CSR := base64.RawURLEncoding.EncodeToString(csr.Raw)
	cmd := exec.Command(iss.Command, iss.Args...)
	cmd.Stdin = strings.NewReader(b64CSR)
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	return &certmagic.IssuedCertificate{
		Certificate: output,
	}, nil
}

// UnmarshalCaddyfile deserializes Caddyfile tokens into iss.
//
//     ... cmd <command> [<args...>]
//
func (iss *CommandIssuer) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	// for d.Next() {
	// }
	return fmt.Errorf("TODO: not implemented")
}

// Interface guards
var (
	_ certmagic.Issuer      = (*CommandIssuer)(nil)
	_ caddy.Provisioner     = (*CommandIssuer)(nil)
	_ caddyfile.Unmarshaler = (*CommandIssuer)(nil)
)
