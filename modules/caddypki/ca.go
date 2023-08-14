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
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/db"
	"github.com/smallstep/truststore"
	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
)

// CA describes a certificate authority, which consists of
// root/signing certificates and various settings pertaining
// to the issuance of certificates and trusting them.
type CA struct {
	// The user-facing name of the certificate authority.
	Name string `json:"name,omitempty"`

	// The name to put in the CommonName field of the
	// root certificate.
	RootCommonName string `json:"root_common_name,omitempty"`

	// The name to put in the CommonName field of the
	// intermediate certificates.
	IntermediateCommonName string `json:"intermediate_common_name,omitempty"`

	// The lifetime for the intermediate certificates
	IntermediateLifetime caddy.Duration `json:"intermediate_lifetime,omitempty"`

	// Whether Caddy will attempt to install the CA's root
	// into the system trust store, as well as into Java
	// and Mozilla Firefox trust stores. Default: true.
	InstallTrust *bool `json:"install_trust,omitempty"`

	// The root certificate to use; if null, one will be generated.
	Root *KeyPair `json:"root,omitempty"`

	// The intermediate (signing) certificate; if null, one will be generated.
	Intermediate *KeyPair `json:"intermediate,omitempty"`

	// Optionally configure a separate storage module associated with this
	// issuer, instead of using Caddy's global/default-configured storage.
	// This can be useful if you want to keep your signing keys in a
	// separate location from your leaf certificates.
	StorageRaw json.RawMessage `json:"storage,omitempty" caddy:"namespace=caddy.storage inline_key=module"`

	// The unique config-facing ID of the certificate authority.
	// Since the ID is set in JSON config via object key, this
	// field is exported only for purposes of config generation
	// and module provisioning.
	ID string `json:"-"`

	storage     certmagic.Storage
	root, inter *x509.Certificate
	interKey    any // TODO: should we just store these as crypto.Signer?
	mu          *sync.RWMutex

	rootCertPath string // mainly used for logging purposes if trusting
	log          *zap.Logger
	ctx          caddy.Context
}

// Provision sets up the CA.
func (ca *CA) Provision(ctx caddy.Context, id string, log *zap.Logger) error {
	ca.mu = new(sync.RWMutex)
	ca.log = log.Named("ca." + id)
	ca.ctx = ctx

	if id == "" {
		return fmt.Errorf("CA ID is required (use 'local' for the default CA)")
	}
	ca.mu.Lock()
	ca.ID = id
	ca.mu.Unlock()

	if ca.StorageRaw != nil {
		val, err := ctx.LoadModule(ca, "StorageRaw")
		if err != nil {
			return fmt.Errorf("loading storage module: %v", err)
		}
		cmStorage, err := val.(caddy.StorageConverter).CertMagicStorage()
		if err != nil {
			return fmt.Errorf("creating storage configuration: %v", err)
		}
		ca.storage = cmStorage
	}
	if ca.storage == nil {
		ca.storage = ctx.Storage()
	}

	if ca.Name == "" {
		ca.Name = defaultCAName
	}
	if ca.RootCommonName == "" {
		ca.RootCommonName = defaultRootCommonName
	}
	if ca.IntermediateCommonName == "" {
		ca.IntermediateCommonName = defaultIntermediateCommonName
	}
	if ca.IntermediateLifetime == 0 {
		ca.IntermediateLifetime = caddy.Duration(defaultIntermediateLifetime)
	} else if time.Duration(ca.IntermediateLifetime) >= defaultRootLifetime {
		return fmt.Errorf("intermediate certificate lifetime must be less than root certificate lifetime (%s)", defaultRootLifetime)
	}

	// load the certs and key that will be used for signing
	var rootCert, interCert *x509.Certificate
	var rootKey, interKey crypto.Signer
	var err error
	if ca.Root != nil {
		if ca.Root.Format == "" || ca.Root.Format == "pem_file" {
			ca.rootCertPath = ca.Root.Certificate
		}
		rootCert, rootKey, err = ca.Root.Load()
	} else {
		ca.rootCertPath = "storage:" + ca.storageKeyRootCert()
		rootCert, rootKey, err = ca.loadOrGenRoot()
	}
	if err != nil {
		return err
	}
	if ca.Intermediate != nil {
		interCert, interKey, err = ca.Intermediate.Load()
	} else {
		interCert, interKey, err = ca.loadOrGenIntermediate(rootCert, rootKey)
	}
	if err != nil {
		return err
	}

	ca.mu.Lock()
	ca.root, ca.inter, ca.interKey = rootCert, interCert, interKey
	ca.mu.Unlock()

	return nil
}

// RootCertificate returns the CA's root certificate (public key).
func (ca CA) RootCertificate() *x509.Certificate {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	return ca.root
}

// RootKey returns the CA's root private key. Since the root key is
// not cached in memory long-term, it needs to be loaded from storage,
// which could yield an error.
func (ca CA) RootKey() (any, error) {
	_, rootKey, err := ca.loadOrGenRoot()
	return rootKey, err
}

// IntermediateCertificate returns the CA's intermediate
// certificate (public key).
func (ca CA) IntermediateCertificate() *x509.Certificate {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	return ca.inter
}

// IntermediateKey returns the CA's intermediate private key.
func (ca CA) IntermediateKey() any {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	return ca.interKey
}

// NewAuthority returns a new Smallstep-powered signing authority for this CA.
// Note that we receive *CA (a pointer) in this method to ensure the closure within it, which
// executes at a later time, always has the only copy of the CA so it can access the latest,
// renewed certificates since NewAuthority was called. See #4517 and #4669.
func (ca *CA) NewAuthority(authorityConfig AuthorityConfig) (*authority.Authority, error) {
	// get the root certificate and the issuer cert+key
	rootCert := ca.RootCertificate()

	// set up the signer; cert/key which signs the leaf certs
	var signerOption authority.Option
	if authorityConfig.SignWithRoot {
		// if we're signing with root, we can just pass the
		// cert/key directly, since it's unlikely to expire
		// while Caddy is running (long lifetime)
		var issuerCert *x509.Certificate
		var issuerKey any
		issuerCert = rootCert
		var err error
		issuerKey, err = ca.RootKey()
		if err != nil {
			return nil, fmt.Errorf("loading signing key: %v", err)
		}
		signerOption = authority.WithX509Signer(issuerCert, issuerKey.(crypto.Signer))
	} else {
		// if we're signing with intermediate, we need to make
		// sure it's always fresh, because the intermediate may
		// renew while Caddy is running (medium lifetime)
		signerOption = authority.WithX509SignerFunc(func() ([]*x509.Certificate, crypto.Signer, error) {
			issuerCert := ca.IntermediateCertificate()
			issuerKey := ca.IntermediateKey().(crypto.Signer)
			ca.log.Debug("using intermediate signer",
				zap.String("serial", issuerCert.SerialNumber.String()),
				zap.String("not_before", issuerCert.NotBefore.String()),
				zap.String("not_after", issuerCert.NotAfter.String()))
			return []*x509.Certificate{issuerCert}, issuerKey, nil
		})
	}

	opts := []authority.Option{
		authority.WithConfig(&authority.Config{
			AuthorityConfig: authorityConfig.AuthConfig,
		}),
		signerOption,
		authority.WithX509RootCerts(rootCert),
	}

	// Add a database if we have one
	if authorityConfig.DB != nil {
		opts = append(opts, authority.WithDatabase(*authorityConfig.DB))
	}
	auth, err := authority.NewEmbedded(opts...)
	if err != nil {
		return nil, fmt.Errorf("initializing certificate authority: %v", err)
	}

	return auth, nil
}

func (ca CA) loadOrGenRoot() (rootCert *x509.Certificate, rootKey crypto.Signer, err error) {
	if ca.Root != nil {
		return ca.Root.Load()
	}
	rootCertPEM, err := ca.storage.Load(ca.ctx, ca.storageKeyRootCert())
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, nil, fmt.Errorf("loading root cert: %v", err)
		}

		// TODO: should we require that all or none of the assets are required before overwriting anything?
		rootCert, rootKey, err = ca.genRoot()
		if err != nil {
			return nil, nil, fmt.Errorf("generating root: %v", err)
		}
	}

	if rootCert == nil {
		rootCert, err = pemDecodeSingleCert(rootCertPEM)
		if err != nil {
			return nil, nil, fmt.Errorf("parsing root certificate PEM: %v", err)
		}
	}
	if rootKey == nil {
		rootKeyPEM, err := ca.storage.Load(ca.ctx, ca.storageKeyRootKey())
		if err != nil {
			return nil, nil, fmt.Errorf("loading root key: %v", err)
		}
		rootKey, err = certmagic.PEMDecodePrivateKey(rootKeyPEM)
		if err != nil {
			return nil, nil, fmt.Errorf("decoding root key: %v", err)
		}
	}

	return rootCert, rootKey, nil
}

func (ca CA) genRoot() (rootCert *x509.Certificate, rootKey crypto.Signer, err error) {
	repl := ca.newReplacer()

	rootCert, rootKey, err = generateRoot(repl.ReplaceAll(ca.RootCommonName, ""))
	if err != nil {
		return nil, nil, fmt.Errorf("generating CA root: %v", err)
	}
	rootCertPEM, err := pemEncodeCert(rootCert.Raw)
	if err != nil {
		return nil, nil, fmt.Errorf("encoding root certificate: %v", err)
	}
	err = ca.storage.Store(ca.ctx, ca.storageKeyRootCert(), rootCertPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("saving root certificate: %v", err)
	}
	rootKeyPEM, err := certmagic.PEMEncodePrivateKey(rootKey)
	if err != nil {
		return nil, nil, fmt.Errorf("encoding root key: %v", err)
	}
	err = ca.storage.Store(ca.ctx, ca.storageKeyRootKey(), rootKeyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("saving root key: %v", err)
	}

	return rootCert, rootKey, nil
}

func (ca CA) loadOrGenIntermediate(rootCert *x509.Certificate, rootKey crypto.Signer) (interCert *x509.Certificate, interKey crypto.Signer, err error) {
	interCertPEM, err := ca.storage.Load(ca.ctx, ca.storageKeyIntermediateCert())
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, nil, fmt.Errorf("loading intermediate cert: %v", err)
		}

		// TODO: should we require that all or none of the assets are required before overwriting anything?
		interCert, interKey, err = ca.genIntermediate(rootCert, rootKey)
		if err != nil {
			return nil, nil, fmt.Errorf("generating new intermediate cert: %v", err)
		}
	}

	if interCert == nil {
		interCert, err = pemDecodeSingleCert(interCertPEM)
		if err != nil {
			return nil, nil, fmt.Errorf("decoding intermediate certificate PEM: %v", err)
		}
	}

	if interKey == nil {
		interKeyPEM, err := ca.storage.Load(ca.ctx, ca.storageKeyIntermediateKey())
		if err != nil {
			return nil, nil, fmt.Errorf("loading intermediate key: %v", err)
		}
		interKey, err = certmagic.PEMDecodePrivateKey(interKeyPEM)
		if err != nil {
			return nil, nil, fmt.Errorf("decoding intermediate key: %v", err)
		}
	}

	return interCert, interKey, nil
}

func (ca CA) genIntermediate(rootCert *x509.Certificate, rootKey crypto.Signer) (interCert *x509.Certificate, interKey crypto.Signer, err error) {
	repl := ca.newReplacer()

	interCert, interKey, err = generateIntermediate(repl.ReplaceAll(ca.IntermediateCommonName, ""), rootCert, rootKey, time.Duration(ca.IntermediateLifetime))
	if err != nil {
		return nil, nil, fmt.Errorf("generating CA intermediate: %v", err)
	}
	interCertPEM, err := pemEncodeCert(interCert.Raw)
	if err != nil {
		return nil, nil, fmt.Errorf("encoding intermediate certificate: %v", err)
	}
	err = ca.storage.Store(ca.ctx, ca.storageKeyIntermediateCert(), interCertPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("saving intermediate certificate: %v", err)
	}
	interKeyPEM, err := certmagic.PEMEncodePrivateKey(interKey)
	if err != nil {
		return nil, nil, fmt.Errorf("encoding intermediate key: %v", err)
	}
	err = ca.storage.Store(ca.ctx, ca.storageKeyIntermediateKey(), interKeyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("saving intermediate key: %v", err)
	}

	return interCert, interKey, nil
}

func (ca CA) storageKeyCAPrefix() string {
	return path.Join("pki", "authorities", certmagic.StorageKeys.Safe(ca.ID))
}

func (ca CA) storageKeyRootCert() string {
	return path.Join(ca.storageKeyCAPrefix(), "root.crt")
}

func (ca CA) storageKeyRootKey() string {
	return path.Join(ca.storageKeyCAPrefix(), "root.key")
}

func (ca CA) storageKeyIntermediateCert() string {
	return path.Join(ca.storageKeyCAPrefix(), "intermediate.crt")
}

func (ca CA) storageKeyIntermediateKey() string {
	return path.Join(ca.storageKeyCAPrefix(), "intermediate.key")
}

func (ca CA) newReplacer() *caddy.Replacer {
	repl := caddy.NewReplacer()
	repl.Set("pki.ca.name", ca.Name)
	return repl
}

// installRoot installs this CA's root certificate into the
// local trust store(s) if it is not already trusted. The CA
// must already be provisioned.
func (ca CA) installRoot() error {
	// avoid password prompt if already trusted
	if trusted(ca.root) {
		ca.log.Info("root certificate is already trusted by system",
			zap.String("path", ca.rootCertPath))
		return nil
	}

	ca.log.Warn("installing root certificate (you might be prompted for password)",
		zap.String("path", ca.rootCertPath))

	return truststore.Install(ca.root,
		truststore.WithDebug(),
		truststore.WithFirefox(),
		truststore.WithJava(),
	)
}

// AuthorityConfig is used to help a CA configure
// the underlying signing authority.
type AuthorityConfig struct {
	SignWithRoot bool

	// TODO: should we just embed the underlying authority.Config struct type?
	DB         *db.AuthDB
	AuthConfig *authority.AuthConfig
}

const (
	// DefaultCAID is the default CA ID.
	DefaultCAID = "local"

	defaultCAName                 = "Caddy Local Authority"
	defaultRootCommonName         = "{pki.ca.name} - {time.now.year} ECC Root"
	defaultIntermediateCommonName = "{pki.ca.name} - ECC Intermediate"

	defaultRootLifetime         = 24 * time.Hour * 30 * 12 * 10
	defaultIntermediateLifetime = 24 * time.Hour * 7
)
