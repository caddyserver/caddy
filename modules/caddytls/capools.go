package caddytls

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"

	"github.com/caddyserver/certmagic"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddypki"
)

func init() {
	caddy.RegisterModule(InlineCAPool{})
	caddy.RegisterModule(FileCAPool{})
	caddy.RegisterModule(PKIRootCAPool{})
	caddy.RegisterModule(PKIIntermediateCAPool{})
	caddy.RegisterModule(StoragePool{})
}

// The interface to be implemented by all guest modules part of
// the namespace 'tls.ca_pool.source.'
type CA interface {
	CertPool() *x509.CertPool
}

// InlineCAPool is a certificate authority pool provider coming from
// a DER-encoded certificates in the config
type InlineCAPool struct {
	// A list of base64 DER-encoded CA certificates
	// against which to validate client certificates.
	// Client certs which are not signed by any of
	// these CAs will be rejected.
	TrustedCACerts []string `json:"trusted_ca_certs,omitempty"`

	pool *x509.CertPool
}

// CaddyModule implements caddy.Module.
func (icp InlineCAPool) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "tls.ca_pool.source.inline",
		New: func() caddy.Module {
			return new(InlineCAPool)
		},
	}
}

// Provision implements caddy.Provisioner.
func (icp *InlineCAPool) Provision(ctx caddy.Context) error {
	caPool := x509.NewCertPool()
	for i, clientCAString := range icp.TrustedCACerts {
		clientCA, err := decodeBase64DERCert(clientCAString)
		if err != nil {
			return fmt.Errorf("parsing certificate at index %d: %v", i, err)
		}
		caPool.AddCert(clientCA)
	}
	icp.pool = caPool

	return nil
}

// CertPool implements CA.
func (icp InlineCAPool) CertPool() *x509.CertPool {
	return icp.pool
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (icp *InlineCAPool) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.CountRemainingArgs() > 0 {
			return d.ArgErr()
		}
		for d.NextBlock(0) {
			switch d.Val() {
			case "trust_der":
				icp.TrustedCACerts = append(icp.TrustedCACerts, d.RemainingArgs()...)
			default:
				return fmt.Errorf("unrecognized directive: %s", d.Val())
			}
		}
	}
	return nil
}

// FileCAPool generates trusted root certificates pool from the designated DER and PEM file
type FileCAPool struct {
	// TrustedCACertPEMFiles is a list of PEM file names
	// from which to load certificates of trusted CAs.
	// Client certificates which are not signed by any of
	// these CA certificates will be rejected.
	TrustedCACertPEMFiles []string `json:"pem_files,omitempty"`

	pool *x509.CertPool
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (fcap *FileCAPool) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.CountRemainingArgs() > 0 {
			return d.ArgErr()
		}
		for d.NextBlock(0) {
			switch d.Val() {
			case "trust_pem_file":
				fcap.TrustedCACertPEMFiles = append(fcap.TrustedCACertPEMFiles, d.RemainingArgs()...)
			default:
				return fmt.Errorf("unrecognized directive: %s", d.Val())
			}
		}
	}
	return nil
}

// CaddyModule implements caddy.Module.
func (FileCAPool) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "tls.ca_pool.source.file",
		New: func() caddy.Module {
			return new(FileCAPool)
		},
	}
}

// Loads and decodes the DER and pem files to generate the certificate pool
func (f *FileCAPool) Provision(ctx caddy.Context) error {
	caPool := x509.NewCertPool()
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

// PKIRootCAPool extracts the trusted root certificates from Caddy's native 'pki' app
type PKIRootCAPool struct {
	// List of the CA names that are configured in the `pki` app whose root certificates are trusted
	CA []string `json:"ca,omitempty"`

	ca   []*caddypki.CA
	pool *x509.CertPool
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (*PKIRootCAPool) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	panic("unimplemented")
}

// CaddyModule implements caddy.Module.
func (PKIRootCAPool) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "tls.ca_pool.source.pki_root",
		New: func() caddy.Module {
			return new(PKIRootCAPool)
		},
	}
}

// Loads the PKI app and load the root certificates into the certificate pool
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

// return the certificate pool generated with root certificates from the PKI app
func (p PKIRootCAPool) CertPool() *x509.CertPool {
	return p.pool
}

// PKIIntermediateCAPool extracts the trusted intermediate certificates from Caddy's native 'pki' app
type PKIIntermediateCAPool struct {
	// List of the CA names that are configured in the `pki` app whose intermediate certificates are trusted
	CA []string `json:"ca,omitempty"`

	ca   []*caddypki.CA
	pool *x509.CertPool
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (*PKIIntermediateCAPool) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	panic("unimplemented")
}

// CaddyModule implements caddy.Module.
func (PKIIntermediateCAPool) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "tls.ca_pool.source.pki_intermediate",
		New: func() caddy.Module {
			return new(PKIIntermediateCAPool)
		},
	}
}

// Loads the PKI app and load the intermediate certificates into the certificate pool
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

// return the certificate pool generated with intermediate certificates from the PKI app
func (p PKIIntermediateCAPool) CertPool() *x509.CertPool {
	return p.pool
}

// StoragePool extracts the trusted certificates root from Caddy storage
type StoragePool struct {
	// The storage module where the trusted root certificates are stored. Absent
	// explicit storage implies the use of Caddy default storage.
	StorageRaw json.RawMessage `json:"storage,omitempty" caddy:"namespace=caddy.storage inline_key=module"`

	// The storage key/index to the location of the certificates
	PEMKeys []string `json:"pem_keys,omitempty"`

	storage certmagic.Storage
	pool    *x509.CertPool
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (*StoragePool) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	panic("unimplemented")
}

// CaddyModule implements caddy.Module.
func (StoragePool) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "tls.ca_pool.source.storage",
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

// TLSConfig holds configuration related to the TLS configuration for the
// transport/client.
// copied from with minor modifications: modules/caddyhttp/reverseproxy/httptransport.go
type TLSConfig struct {
	// Provides the guest module that provides the trusted certificate authority (CA) certificates
	CARaw json.RawMessage `json:"ca,omitempty" caddy:"namespace=tls.ca_pool.source inline_key=provider"`

	// If true, TLS verification of server certificates will be disabled.
	// This is insecure and may be removed in the future. Do not use this
	// option except in testing or local development environments.
	InsecureSkipVerify bool `json:"insecure_skip_verify,omitempty"`

	// The duration to allow a TLS handshake to a server. Default: No timeout.
	HandshakeTimeout caddy.Duration `json:"handshake_timeout,omitempty"`

	// The server name used when verifying the certificate received in the TLS
	// handshake. By default, this will use the upstream address' host part.
	// You only need to override this if your upstream address does not match the
	// certificate the upstream is likely to use. For example if the upstream
	// address is an IP address, then you would need to configure this to the
	// hostname being served by the upstream server. Currently, this does not
	// support placeholders because the TLS config is not provisioned on each
	// connection, so a static value must be used.
	ServerName string `json:"server_name,omitempty"`

	// TLS renegotiation level. TLS renegotiation is the act of performing
	// subsequent handshakes on a connection after the first.
	// The level can be:
	//  - "never": (the default) disables renegotiation.
	//  - "once": allows a remote server to request renegotiation once per connection.
	//  - "freely": allows a remote server to repeatedly request renegotiation.
	Renegotiation string `json:"renegotiation,omitempty"`
}

// MakeTLSClientConfig returns a tls.Config usable by a client to a backend.
// If there is no custom TLS configuration, a nil config may be returned.
// copied from with minor modifications: modules/caddyhttp/reverseproxy/httptransport.go
func (t TLSConfig) makeTLSClientConfig(ctx caddy.Context) (*tls.Config, error) {
	cfg := new(tls.Config)

	if t.CARaw != nil {
		caRaw, err := ctx.LoadModule(t, "CARaw")
		if err != nil {
			return nil, err
		}
		ca := caRaw.(CA)
		cfg.RootCAs = ca.CertPool()
	}

	// Renegotiation
	switch t.Renegotiation {
	case "never", "":
		cfg.Renegotiation = tls.RenegotiateNever
	case "once":
		cfg.Renegotiation = tls.RenegotiateOnceAsClient
	case "freely":
		cfg.Renegotiation = tls.RenegotiateFreelyAsClient
	default:
		return nil, fmt.Errorf("invalid TLS renegotiation level: %v", t.Renegotiation)
	}

	// override for the server name used verify the TLS handshake
	cfg.ServerName = t.ServerName

	// throw all security out the window
	cfg.InsecureSkipVerify = t.InsecureSkipVerify

	// only return a config if it's not empty
	if reflect.DeepEqual(cfg, new(tls.Config)) {
		return nil, nil
	}

	return cfg, nil
}

// The HTTPCertPool fetches the trusted root certificates from HTTP(S)
// endpoints. The TLS connection properties can be customized, including custom
// trusted root certificate. One example usage of this module is to get the trusted
// certificates from another Caddy instance that is running the PKI app and ACME server.
type HTTPCertPool struct {
	// the list of URLs that respond with PEM-encoded certificates to trust.
	Endpoints []string `json:"endpoints,omitempty"`

	// Customize the TLS connection knobs to used during the HTTP call
	TLS *TLSConfig `json:"tls,omitempty"`

	pool *x509.CertPool
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (*HTTPCertPool) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	panic("unimplemented")
}

// CaddyModule implements caddy.Module.
func (*HTTPCertPool) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "tls.ca_pool.source.http",
		New: func() caddy.Module {
			return new(StoragePool)
		},
	}
}

// Provision implements caddy.Provisioner.
func (hcp *HTTPCertPool) Provision(ctx caddy.Context) error {
	caPool := x509.NewCertPool()

	customTransport := http.DefaultTransport.(*http.Transport).Clone()
	if hcp.TLS != nil {
		tlsConfig, err := hcp.TLS.makeTLSClientConfig(ctx)
		if err != nil {
			return err
		}
		customTransport.TLSClientConfig = tlsConfig
	}

	var httpClient *http.Client
	*httpClient = *http.DefaultClient
	httpClient.Transport = customTransport

	for _, uri := range hcp.Endpoints {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
		if err != nil {
			return err
		}
		res, err := httpClient.Do(req)
		if err != nil {
			return err
		}
		pembs, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			return err
		}
		if !caPool.AppendCertsFromPEM(pembs) {
			return fmt.Errorf("failed to add certs from URL: %s", uri)
		}
	}
	hcp.pool = caPool
	return nil
}

// CertPool return the certificate pool generated from the HTTP responses
func (hcp HTTPCertPool) CertPool() *x509.CertPool {
	return hcp.pool
}

// LazyCertPool defers the generation of the certificate pool from the
// guest module to demand-time rather than at provisionig time. The gain of the
// lazy load adds a risk of failure to load the certificates at demand time
// because the validation that's typically done at provisioning is deferred.
// The validation can be enforced to run before runtime by setting
// `EagerValidation`/`eager_validation` to `true`. It is the operator's responsibility
// to ensure the resources are available if `EagerValidation`/`eager_validation`
// is set to `true`. The module also incurs performance cost at every demand.
type LazyCertPool struct {
	// Provides the guest module that provides the trusted certificate authority (CA) certificates
	CARaw json.RawMessage `json:"ca,omitempty" caddy:"namespace=tls.ca_pool.source inline_key=provider"`

	// Whether the validation step should try to load and provision the guest module to validate
	// the correctness of the configuration. Depeneding on the type of the guest module,
	// the resources may not be available at validation time. It is the
	// operator's responsibility to ensure the resources are available if `EagerValidation`/`eager_validation`
	// is set to `true`.
	EagerValidation bool `json:"eager_validation,omitempty"`

	ctx caddy.Context
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (*LazyCertPool) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	panic("unimplemented")
}

// CaddyModule implements caddy.Module.
func (*LazyCertPool) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "tls.ca_pool.source.lazy",
		New: func() caddy.Module {
			return new(LazyCertPool)
		},
	}
}

// Provision implements caddy.Provisioner.
func (lcp *LazyCertPool) Provision(ctx caddy.Context) error {
	lcp.ctx = ctx
	return nil
}

// If EagerValidation is `true`, it attempts to load and provision the guest module
// to ensure the guesst module's configuration is correct. Depeneding on the type of the
// guest module, the resources may not be available at validation time. It is the
// operator's responsibility to ensure the resources are available if `EagerValidation` is
// set to `true`.
func (lcp *LazyCertPool) Validate() error {
	if lcp.EagerValidation {
		_, err := lcp.ctx.LoadModule(lcp, "CARaw")
		return err
	}
	return nil
}

// CertPool loads the guest module and returns the CertPool from there
// TODO: Cache?
func (lcp *LazyCertPool) CertPool() *x509.CertPool {
	caRaw, err := lcp.ctx.LoadModule(lcp, "CARaw")
	if err != nil {
		return nil
	}
	ca := caRaw.(CA)
	return ca.CertPool()
}

var (
	_ caddy.Module          = (*InlineCAPool)(nil)
	_ caddy.Provisioner     = (*InlineCAPool)(nil)
	_ CA                    = (*InlineCAPool)(nil)
	_ caddyfile.Unmarshaler = (*InlineCAPool)(nil)

	_ caddy.Module          = (*FileCAPool)(nil)
	_ caddy.Provisioner     = (*FileCAPool)(nil)
	_ CA                    = (*FileCAPool)(nil)
	_ caddyfile.Unmarshaler = (*FileCAPool)(nil)

	_ caddy.Module          = (*PKIRootCAPool)(nil)
	_ caddy.Provisioner     = (*PKIRootCAPool)(nil)
	_ CA                    = (*PKIRootCAPool)(nil)
	_ caddyfile.Unmarshaler = (*PKIRootCAPool)(nil)

	_ caddy.Module          = (*PKIIntermediateCAPool)(nil)
	_ caddy.Provisioner     = (*PKIIntermediateCAPool)(nil)
	_ CA                    = (*PKIIntermediateCAPool)(nil)
	_ caddyfile.Unmarshaler = (*PKIIntermediateCAPool)(nil)

	_ caddy.Module          = (*StoragePool)(nil)
	_ caddy.Provisioner     = (*StoragePool)(nil)
	_ CA                    = (*StoragePool)(nil)
	_ caddyfile.Unmarshaler = (*StoragePool)(nil)

	_ caddy.Module          = (*HTTPCertPool)(nil)
	_ caddy.Provisioner     = (*HTTPCertPool)(nil)
	_ CA                    = (*HTTPCertPool)(nil)
	_ caddyfile.Unmarshaler = (*HTTPCertPool)(nil)

	_ caddy.Module          = (*LazyCertPool)(nil)
	_ caddy.Provisioner     = (*LazyCertPool)(nil)
	_ caddy.Validator       = (*LazyCertPool)(nil)
	_ CA                    = (*LazyCertPool)(nil)
	_ caddyfile.Unmarshaler = (*LazyCertPool)(nil)
)