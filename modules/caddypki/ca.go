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
	"encoding/json"
	"fmt"
	"path"
	"strconv"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
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

	// If true, Caddy will attempt to install the CA's root
	// into the system trust store.
	InstallTrust bool `json:"install_trust,omitempty"`

	Root         *KeyPair `json:"root,omitempty"`
	Intermediate *KeyPair `json:"intermediate,omitempty"`

	// TODO: ability to configure:
	// - Root and intermedmiate lifeties -- FIXME: be sure to disallow child cert lifetimes that would extend beyond parent lifetimes

	// Optionally configure a separate storage module associated with this
	// issuer, instead of using Caddy's global/default-configured storage.
	// This can be useful if you want to keep your signing keys in a
	// separate location from your leaf certificates.
	StorageRaw json.RawMessage `json:"storage,omitempty" caddy:"namespace=caddy.storage inline_key=module"`

	id          string
	storage     certmagic.Storage
	root, inter *x509.Certificate
	interKey    interface{} // TODO: should we just store this as a crypto.Signer?
	mu          *sync.RWMutex

	rootCertPath string // mainly used for logging purposes if trusting
	log          *zap.Logger
}

// Provision sets up the CA.
func (ca *CA) Provision(ctx caddy.Context, id string, log *zap.Logger) error {
	ca.mu = new(sync.RWMutex)
	ca.log = log.Named("ca." + id)

	if id == "" {
		return fmt.Errorf("CA ID is required (use 'local' for the default CA)")
	}
	ca.mu.Lock()
	ca.id = id
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

	// load the certs and key that will be used for signing
	var rootCert, interCert *x509.Certificate
	var rootKey, interKey interface{}
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

// ID returns the CA's ID, as given by the user in the config.
func (ca CA) ID() string {
	return ca.id
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
func (ca CA) RootKey() (interface{}, error) {
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
func (ca CA) IntermediateKey() interface{} {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	return ca.interKey
}

func (ca CA) loadOrGenRoot() (rootCert *x509.Certificate, rootKey interface{}, err error) {
	rootCertPEM, err := ca.storage.Load(ca.storageKeyRootCert())
	if err != nil {
		if _, ok := err.(certmagic.ErrNotExist); !ok {
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
		rootKeyPEM, err := ca.storage.Load(ca.storageKeyRootKey())
		if err != nil {
			return nil, nil, fmt.Errorf("loading root key: %v", err)
		}
		rootKey, err = pemDecodePrivateKey(rootKeyPEM)
		if err != nil {
			return nil, nil, fmt.Errorf("decoding root key: %v", err)
		}
	}

	return rootCert, rootKey, nil
}

func (ca CA) genRoot() (rootCert *x509.Certificate, rootKey interface{}, err error) {
	repl := ca.newReplacer()

	rootCert, rootKey, err = generateRoot(repl.ReplaceAll(ca.RootCommonName, ""))
	if err != nil {
		return nil, nil, fmt.Errorf("generating CA root: %v", err)
	}
	rootCertPEM, err := pemEncodeCert(rootCert.Raw)
	if err != nil {
		return nil, nil, fmt.Errorf("encoding root certificate: %v", err)
	}
	err = ca.storage.Store(ca.storageKeyRootCert(), rootCertPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("saving root certificate: %v", err)
	}
	rootKeyPEM, err := pemEncodePrivateKey(rootKey)
	if err != nil {
		return nil, nil, fmt.Errorf("encoding root key: %v", err)
	}
	err = ca.storage.Store(ca.storageKeyRootKey(), rootKeyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("saving root key: %v", err)
	}

	return rootCert, rootKey, nil
}

func (ca CA) loadOrGenIntermediate(rootCert *x509.Certificate, rootKey interface{}) (interCert *x509.Certificate, interKey interface{}, err error) {
	interCertPEM, err := ca.storage.Load(ca.storageKeyIntermediateCert())
	if err != nil {
		if _, ok := err.(certmagic.ErrNotExist); !ok {
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
		interKeyPEM, err := ca.storage.Load(ca.storageKeyIntermediateKey())
		if err != nil {
			return nil, nil, fmt.Errorf("loading intermediate key: %v", err)
		}
		interKey, err = pemDecodePrivateKey(interKeyPEM)
		if err != nil {
			return nil, nil, fmt.Errorf("decoding intermediate key: %v", err)
		}
	}

	return interCert, interKey, nil
}

func (ca CA) genIntermediate(rootCert *x509.Certificate, rootKey interface{}) (interCert *x509.Certificate, interKey interface{}, err error) {
	repl := ca.newReplacer()

	rootKeyPEM, err := ca.storage.Load(ca.storageKeyRootKey())
	if err != nil {
		return nil, nil, fmt.Errorf("loading root key to sign new intermediate: %v", err)
	}
	rootKey, err = pemDecodePrivateKey(rootKeyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("decoding root key: %v", err)
	}
	interCert, interKey, err = generateIntermediate(repl.ReplaceAll(ca.IntermediateCommonName, ""), rootCert, rootKey)
	if err != nil {
		return nil, nil, fmt.Errorf("generating CA intermediate: %v", err)
	}
	interCertPEM, err := pemEncodeCert(interCert.Raw)
	if err != nil {
		return nil, nil, fmt.Errorf("encoding intermediate certificate: %v", err)
	}
	err = ca.storage.Store(ca.storageKeyIntermediateCert(), interCertPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("saving intermediate certificate: %v", err)
	}
	interKeyPEM, err := pemEncodePrivateKey(interKey)
	if err != nil {
		return nil, nil, fmt.Errorf("encoding intermediate key: %v", err)
	}
	err = ca.storage.Store(ca.storageKeyIntermediateKey(), interKeyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("saving intermediate key: %v", err)
	}

	return interCert, interKey, nil
}

func (ca CA) storageKeyCAPrefix() string {
	return path.Join("pki", "authorities", certmagic.StorageKeys.Safe(ca.id))
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
	// TODO: these are all temporary until I get this more organized
	repl := caddy.NewReplacer()
	repl.Set("pki.ca.name", ca.Name)
	repl.Set("year", strconv.Itoa(time.Now().Year()))
	repl.Set("pki.ca.cert.key_type", "ECC") // TODO: set this properly
	return repl
}

const (
	defaultCAID                   = "local"
	defaultCAName                 = "Caddy Local Authority"
	defaultRootCommonName         = "{pki.ca.name} - {year} {pki.ca.cert.key_type} Root"
	defaultIntermediateCommonName = "{pki.ca.name} - {pki.ca.cert.key_type} Intermediate"

	defaultRootLifetime         = 24 * time.Hour * 30 * 12 * 10
	defaultIntermediateLifetime = 24 * time.Hour * 7
)
