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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/go-acme/lego/certificate"
	"github.com/mholt/certmagic"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/db"
	"github.com/smallstep/certificates/pki"
	"github.com/smallstep/cli/crypto/randutil"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/ui"
	"github.com/smallstep/cli/utils"
	"go.uber.org/zap"
)

// SmallStepManagerMaker provides an adapter to manage provisioning a new Small Step Server
type SmallStepManagerMaker struct {
	AcmeManager *ACMEManagerMaker
	DB          db.AuthDB
	Authority   *authority.Authority
	tlsApp      *TLS
}

type inMemoryDB struct {
}

func (db *inMemoryDB) IsRevoked(sn string) (bool, error) {
	caddy.Log().Info("SmallStep.inMemoryDB IsRevoked", zap.String("sn", sn))
	return false, nil
}

func (db *inMemoryDB) Revoke(rci *db.RevokedCertificateInfo) error {
	caddy.Log().Info("SmallStep.inMemoryDB Revoke", zap.String("rci", rci.Reason))
	return nil
}

func (db *inMemoryDB) StoreCertificate(crt *x509.Certificate) error {
	caddy.Log().Info("SmallStep.inMemoryDB Store", zap.String("dns", crt.DNSNames[0]))
	return nil
}
func (db *inMemoryDB) UseToken(id, tok string) (bool, error) {
	caddy.Log().Info("SmallStep.inMemoryDB UseToken", zap.String("id", id), zap.String("tok", tok))
	return false, nil
}
func (db *inMemoryDB) Shutdown() error {
	caddy.Log().Info("SmallStep.inMemoryDB Shutdown")
	return nil
}

// NewSmallStepManager creates a new small step manager
func NewSmallStepManager(ctx caddy.Context, acme *ACMEManagerMaker) (*SmallStepManagerMaker, error) {
	caddy.Log().Info("SmallStep.Provision")

	appVal, err := ctx.App("tls")
	if err != nil {
		return nil, err
	}

	m := &SmallStepManagerMaker{
		AcmeManager: acme,
		DB:          &inMemoryDB{},
		tlsApp:      appVal.(*TLS),
	}

	var config *authority.Config

	if _, err := os.Stat(pki.GetConfigPath()); os.IsNotExist(err) {
		// create a new certificate authority
		config, err = createNewCA()
		if err != nil {
			return m, err
		}
	} else {
		// load an existing config file (requires the password is stored locally)
		config, err = authority.LoadConfiguration(pki.GetConfigPath() + "/ca.json")
		if err != nil {
			return m, err
		}

		if config.Password == "" {
			return nil, errors.New("Unable to use small step ca without an accessible password. Please add the password to ca.json")
		}
	}

	a, err := authority.New(config, authority.WithDatabase(m.DB))
	if err != nil {
		caddy.Log().Error("SmallStep provision error", zap.Error(err))
		return m, err
	}

	m.Authority = a

	return m, nil
}

func createNewCA() (*authority.Config, error) {

	name := "ca.local"
	dns := "127.0.0.1"
	address := "127.0.0.1:9000"

	pwd, err := randutil.ASCII(32)
	if err != nil {
		return nil, err
	}
	password := []byte(pwd)

	p, err := pki.New(pki.GetPublicPath(), pki.GetSecretsPath(), pki.GetConfigPath())
	if err != nil {
		return nil, err
	}

	p.SetAddress(address)
	p.SetDNSNames([]string{dns})

	ui.Println("Generating root certificate...")
	rootCrt, rootKey, err := p.GenerateRootCertificate(name+" Root CA", password)
	if err != nil {
		return nil, err
	}

	ui.Println("Generating intermediate certificate...")
	err = p.GenerateIntermediateCertificate(name+" Intermediate CA", rootCrt, rootKey, password)
	if err != nil {
		return nil, err
	}

	// Generate provisioner
	p.SetProvisioner("admin")
	ui.Println("Generating admin provisioner...")
	if err = p.GenerateKeyPairs(password); err != nil {
		return nil, err
	}

	// Generate and write configuration
	caConfig, err := p.GenerateConfig()
	if err != nil {
		return nil, err
	}

	// set the current password
	caConfig.Password = string(password)

	b, err := json.MarshalIndent(caConfig, "", "   ")
	if err != nil {
		return nil, err
	}
	if err = utils.WriteFile(p.GetCAConfigPath(), b, 0666); err != nil {
		return nil, errs.FileError(err, p.GetCAConfigPath())
	}

	return caConfig, nil
}

// NewManager is a no-op to satisfy the ManagerMaker interface,
// because this manager type is a special case.
func (m SmallStepManagerMaker) NewManager(interactive bool) (certmagic.Manager, error) {
	return m, nil
}

func getPrivateKey() (*rsa.PrivateKey, []byte, error) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pemdata := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		},
	)

	return key, pemdata, nil
}

// Obtain a certificate
func (m SmallStepManagerMaker) Obtain(ctx context.Context, name string) error {
	caddy.Log().Info("SmallStep.Obtain", zap.String("name", name))

	key, pemKey, err := getPrivateKey()
	if err != nil {
		return err
	}

	// generate a csr
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			Organization: []string{"Internal CA"},
			CommonName:   name,
		},
		DNSNames:           []string{name},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	derBytes, _ := x509.CreateCertificateRequest(rand.Reader, &template, key)

	parsedCsr, err := x509.ParseCertificateRequest(derBytes)
	if err != nil {
		return err
	}

	opts := provisioner.Options{
		NotBefore: provisioner.NewTimeDuration(time.Now().Add(-time.Hour)),
		NotAfter:  provisioner.NewTimeDuration(time.Now().Add(10 * time.Hour)),
	}

	c1, c2, err := m.Authority.Sign(parsedCsr, opts)
	if err != nil {
		return err
	}

	c1PEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: c1.Raw,
	})

	c2PEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: c2.Raw,
	})

	certChain := append(c1PEM[:], c2PEM[:]...)

	//TODO: not sure why this needs to be defaulted
	//TODO: attempted to pull from the tlsApp.getConfigForName(name) but it was empty
	prefix := certmagic.Default.CA //"https://acme-v02.api.letsencrypt.org/directory"

	cert := certificate.Resource{
		Domain: name,
	}

	metaBytes, err := json.MarshalIndent(&cert, "", "\t")
	if err != nil {
		return fmt.Errorf("encoding certificate metadata: %v", err)
	}

	err = m.AcmeManager.storage.Store(certmagic.StorageKeys.SiteCert(prefix, name), certChain)
	if err != nil {
		return err
	}

	err = m.AcmeManager.storage.Store(certmagic.StorageKeys.SitePrivateKey(prefix, name), pemKey)
	if err != nil {
		return err
	}

	err = m.AcmeManager.storage.Store(certmagic.StorageKeys.SiteMeta(prefix, name), metaBytes)
	if err != nil {
		return err
	}

	return err
}

// Renew a certificate for a domain
func (m SmallStepManagerMaker) Renew(ctx context.Context, name string) error {
	caddy.Log().Info("SmallStep.Renew", zap.String("name", name))
	return m.Obtain(ctx, name)
}

// Revoke a certificate for a domain
func (m SmallStepManagerMaker) Revoke(ctx context.Context, name string) error {
	caddy.Log().Info("SmallStep.Revoke", zap.String("name", name))
	return nil
}

// Interface guard
var _ ManagerMaker = (*SmallStepManagerMaker)(nil)
var _ certmagic.Manager = (*SmallStepManagerMaker)(nil)
