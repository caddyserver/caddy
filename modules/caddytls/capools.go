package caddytls

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"

	"github.com/caddyserver/certmagic"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddypki"
)

func init() {
	caddy.RegisterModule(FileCAPool{})
	caddy.RegisterModule(PKIRootCAPool{})
	caddy.RegisterModule(PKIIntermediateCAPool{})
	caddy.RegisterModule(StoragePool{})
}

type CA interface {
	CertPool() *x509.CertPool
}

type FileCAPool struct {
	// A list of base64 DER-encoded CA certificates
	// against which to validate client certificates.
	// Client certs which are not signed by any of
	// these CAs will be rejected.
	TrustedCACerts []string `json:"trusted_ca_certs,omitempty"`

	// TrustedCACertPEMFiles is a list of PEM file names
	// from which to load certificates of trusted CAs.
	// Client certificates which are not signed by any of
	// these CA certificates will be rejected.
	TrustedCACertPEMFiles []string `json:"trusted_ca_certs_pem_files,omitempty"`

	pool *x509.CertPool
}

// CaddyModule implements caddy.Module.
func (FileCAPool) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "tls.client_auth.ca.file",
		New: func() caddy.Module {
			return new(FileCAPool)
		},
	}
}

func (f *FileCAPool) Provision(ctx caddy.Context) error {
	caPool := x509.NewCertPool()
	for _, clientCAString := range f.TrustedCACerts {
		clientCA, err := decodeBase64DERCert(clientCAString)
		if err != nil {
			return fmt.Errorf("parsing certificate: %v", err)
		}
		caPool.AddCert(clientCA)
	}
	for _, pemFile := range f.TrustedCACertPEMFiles {
		pemContents, err := os.ReadFile(pemFile)
		if err != nil {
			return fmt.Errorf("reading %s: %v", pemFile, err)
		}
		caPool.AppendCertsFromPEM(pemContents)
	}
	f.pool = caPool
	return nil
}

func (f FileCAPool) CertPool() *x509.CertPool {
	return f.pool
}

type PKIRootCAPool struct {
	CA   []string `json:"ca,omitempty"`
	ca   []*caddypki.CA
	pool *x509.CertPool
}

// CaddyModule implements caddy.Module.
func (PKIRootCAPool) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "tls.client_auth.ca.pki_root",
		New: func() caddy.Module {
			return new(PKIRootCAPool)
		},
	}
}

// Provision implements caddy.Provisioner.
func (p *PKIRootCAPool) Provision(ctx caddy.Context) error {
	pkiApp := ctx.AppIfConfigured("pki")
	if pkiApp == nil {
		return fmt.Errorf("PKI app not configured")
	}
	pki := pkiApp.(*caddypki.PKI)
	for _, caID := range p.CA {
		c, err := pki.GetCA(ctx, caID)
		if err != nil || c == nil {
			return fmt.Errorf("getting CA %s: %v", caID, err)
		}
		p.ca = append(p.ca, c)
	}

	caPool := x509.NewCertPool()
	for _, ca := range p.ca {
		caPool.AddCert(ca.RootCertificate())
	}
	p.pool = caPool

	return nil
}

func (p PKIRootCAPool) CertPool() *x509.CertPool {
	return p.pool
}

type PKIIntermediateCAPool struct {
	CA   []string `json:"ca,omitempty"`
	ca   []*caddypki.CA
	pool *x509.CertPool
}

// CaddyModule implements caddy.Module.
func (PKIIntermediateCAPool) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "tls.client_auth.ca.pki_intermediate",
		New: func() caddy.Module {
			return new(PKIIntermediateCAPool)
		},
	}
}

// Provision implements caddy.Provisioner.
func (p *PKIIntermediateCAPool) Provision(ctx caddy.Context) error {
	pkiApp := ctx.AppIfConfigured("pki")
	if pkiApp == nil {
		return fmt.Errorf("PKI app not configured")
	}
	pki := pkiApp.(*caddypki.PKI)
	for _, caID := range p.CA {
		c, err := pki.GetCA(ctx, caID)
		if err != nil || c == nil {
			return fmt.Errorf("getting CA %s: %v", caID, err)
		}
		p.ca = append(p.ca, c)
	}

	caPool := x509.NewCertPool()
	for _, ca := range p.ca {
		caPool.AddCert(ca.IntermediateCertificate())
	}
	p.pool = caPool

	return nil
}

func (p PKIIntermediateCAPool) CertPool() *x509.CertPool {
	return p.pool
}

type StoragePool struct {
	StorageRaw json.RawMessage `json:"storage,omitempty" caddy:"namespace=caddy.storage inline_key=module"`
	PEMKeys    []string        `json:"pem_keys,omitempty"`
	storage    certmagic.Storage
	pool       *x509.CertPool
}

// CaddyModule implements caddy.Module.
func (StoragePool) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "tls.client_auth.ca.storage",
		New: func() caddy.Module {
			return new(StoragePool)
		},
	}
}

// Provision implements caddy.Provisioner.
func (ca *StoragePool) Provision(ctx caddy.Context) error {
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

	caPool := x509.NewCertPool()
	for _, caID := range ca.PEMKeys {
		bs, err := ca.storage.Load(ctx, caID)
		if err != nil {
			return fmt.Errorf("error loading cert '%s' from storage: %s", caID, err)
		}
		if !caPool.AppendCertsFromPEM(bs) {
			return fmt.Errorf("failed to add certificate '%s' to pool", caID)
		}
	}
	ca.pool = caPool

	return nil
}

func (p StoragePool) CertPool() *x509.CertPool {
	return p.pool
}

var (
	_ caddy.Module      = (*FileCAPool)(nil)
	_ caddy.Provisioner = (*FileCAPool)(nil)
	_ CA                = (*FileCAPool)(nil)

	_ caddy.Module      = (*PKIRootCAPool)(nil)
	_ caddy.Provisioner = (*PKIRootCAPool)(nil)
	_ CA                = (*PKIRootCAPool)(nil)

	_ caddy.Module      = (*PKIIntermediateCAPool)(nil)
	_ caddy.Provisioner = (*PKIIntermediateCAPool)(nil)
	_ CA                = (*PKIIntermediateCAPool)(nil)

	_ caddy.Module      = (*StoragePool)(nil)
	_ caddy.Provisioner = (*StoragePool)(nil)
	_ CA                = (*StoragePool)(nil)
)
