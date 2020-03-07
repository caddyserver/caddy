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
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddypki"
	"github.com/caddyserver/certmagic"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/cli/crypto/x509util"
)

func init() {
	caddy.RegisterModule(InternalIssuer{})
}

// InternalIssuer is a certificate issuer that generates
// certificates internally using a locally-configured
// CA which can be customized using the `pki` app.
type InternalIssuer struct {
	// The ID of the CA to use for signing. The default
	// CA ID is "local". The CA can be configured with the
	// `pki` app.
	CA string `json:"ca,omitempty"`

	// The validity period of certificates.
	Lifetime caddy.Duration `json:"lifetime,omitempty"`

	ca *caddypki.CA
}

// CaddyModule returns the Caddy module information.
func (InternalIssuer) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.issuance.internal",
		New: func() caddy.Module { return new(InternalIssuer) },
	}
}

// Provision sets up the issuer.
func (li *InternalIssuer) Provision(ctx caddy.Context) error {
	// get a reference to the configured CA
	appModule, err := ctx.App("pki")
	if err != nil {
		return err
	}
	pkiApp := appModule.(*caddypki.PKI)
	if li.CA == "" {
		li.CA = defaultInternalCAName
	}
	ca, ok := pkiApp.CAs[li.CA]
	if !ok {
		return fmt.Errorf("no certificate authority configured with id: %s", li.CA)
	}
	li.ca = ca

	// set any other default values
	if li.Lifetime == 0 {
		li.Lifetime = caddy.Duration(defaultInternalCertLifetime)
	}

	return nil
}

// IssuerKey returns the unique issuer key for the
// confgured CA endpoint.
func (li InternalIssuer) IssuerKey() string {
	return li.ca.ID()
}

// Issue issues a certificate to satisfy the CSR.
func (li InternalIssuer) Issue(ctx context.Context, csr *x509.CertificateRequest) (*certmagic.IssuedCertificate, error) {
	// prepare the signing authority
	// TODO: eliminate placeholders / needless values
	cfg := &authority.Config{
		Address:          "placeholder_Address:1",
		Root:             []string{"placeholder_Root"},
		IntermediateCert: "placeholder_IntermediateCert",
		IntermediateKey:  "placeholder_IntermediateKey",
		DNSNames:         []string{"placeholder_DNSNames"},
		AuthorityConfig: &authority.AuthConfig{
			Provisioners: provisioner.List{},
		},
	}
	interCert := li.ca.IntermediateCertificate()
	auth, err := authority.New(cfg,
		authority.WithX509Signer(interCert, li.ca.IntermediateKey().(crypto.Signer)),
		authority.WithX509RootCerts(li.ca.RootCertificate()),
	)
	if err != nil {
		return nil, fmt.Errorf("initializing certificate authority: %v", err)
	}

	// ensure issued certificate does not expire later than its issuer
	lifetime := time.Duration(li.Lifetime)
	if time.Now().Add(lifetime).After(interCert.NotAfter) {
		// TODO: log this
		lifetime = interCert.NotAfter.Sub(time.Now())
	}

	certChain, err := auth.Sign(csr, provisioner.Options{},
		profileDefaultDuration(li.Lifetime),
	)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	for _, cert := range certChain {
		err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
		if err != nil {
			return nil, err
		}
	}

	return &certmagic.IssuedCertificate{
		Certificate: buf.Bytes(),
	}, nil
}

// TODO: borrowing from https://github.com/smallstep/certificates/blob/806abb6232a5691198b891d76b9898ea7f269da0/authority/provisioner/sign_options.go#L191-L211
// as per https://github.com/smallstep/certificates/issues/198.
// profileDefaultDuration is a wrapper against x509util.WithOption to conform
// the SignOption interface.
type profileDefaultDuration time.Duration

// TODO: is there a better way to set cert lifetimes than copying from the smallstep libs?
func (d profileDefaultDuration) Option(so provisioner.Options) x509util.WithOption {
	var backdate time.Duration
	notBefore := so.NotBefore.Time()
	if notBefore.IsZero() {
		notBefore = time.Now().Truncate(time.Second)
		backdate = -1 * so.Backdate
	}
	notAfter := so.NotAfter.RelativeTime(notBefore)
	return func(p x509util.Profile) error {
		fn := x509util.WithNotBeforeAfterDuration(notBefore, notAfter, time.Duration(d))
		if err := fn(p); err != nil {
			return err
		}
		crt := p.Subject()
		crt.NotBefore = crt.NotBefore.Add(backdate)
		return nil
	}
}

const (
	defaultInternalCAName       = "local"
	defaultInternalCertLifetime = 12 * time.Hour
)

// Interface guards
var (
	_ caddy.Provisioner = (*InternalIssuer)(nil)
	_ certmagic.Issuer  = (*InternalIssuer)(nil)
)
