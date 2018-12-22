// Copyright 2015 Matthew Holt
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

package certmagic

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"golang.org/x/crypto/ocsp"
)

// stapleOCSP staples OCSP information to cert for hostname name.
// If you have it handy, you should pass in the PEM-encoded certificate
// bundle; otherwise the DER-encoded cert will have to be PEM-encoded.
// If you don't have the PEM blocks already, just pass in nil.
//
// Errors here are not necessarily fatal, it could just be that the
// certificate doesn't have an issuer URL.
func (certCache *Cache) stapleOCSP(cert *Certificate, pemBundle []byte) error {
	if pemBundle == nil {
		// we need a PEM encoding only for some function calls below
		bundle := new(bytes.Buffer)
		for _, derBytes := range cert.Certificate.Certificate {
			pem.Encode(bundle, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
		}
		pemBundle = bundle.Bytes()
	}

	var ocspBytes []byte
	var ocspResp *ocsp.Response
	var ocspErr error
	var gotNewOCSP bool

	// First try to load OCSP staple from storage and see if
	// we can still use it.
	ocspStapleKey := StorageKeys.OCSPStaple(cert, pemBundle)
	cachedOCSP, err := certCache.storage.Load(ocspStapleKey)
	if err == nil {
		resp, err := ocsp.ParseResponse(cachedOCSP, nil)
		if err == nil {
			if freshOCSP(resp) {
				// staple is still fresh; use it
				ocspBytes = cachedOCSP
				ocspResp = resp
			}
		} else {
			// invalid contents; delete the file
			// (we do this independently of the maintenance routine because
			// in this case we know for sure this should be a staple file
			// because we loaded it by name, whereas the maintenance routine
			// just iterates the list of files, even if somehow a non-staple
			// file gets in the folder. in this case we are sure it is corrupt.)
			err := certCache.storage.Delete(ocspStapleKey)
			if err != nil {
				log.Printf("[WARNING] Unable to delete invalid OCSP staple file: %v", err)
			}
		}
	}

	// If we couldn't get a fresh staple by reading the cache,
	// then we need to request it from the OCSP responder
	if ocspResp == nil || len(ocspBytes) == 0 {
		ocspBytes, ocspResp, ocspErr = getOCSPForCert(pemBundle)
		if ocspErr != nil {
			// An error here is not a problem because a certificate may simply
			// not contain a link to an OCSP server. But we should log it anyway.
			// There's nothing else we can do to get OCSP for this certificate,
			// so we can return here with the error.
			return fmt.Errorf("no OCSP stapling for %v: %v", cert.Names, ocspErr)
		}
		gotNewOCSP = true
	}

	// By now, we should have a response. If good, staple it to
	// the certificate. If the OCSP response was not loaded from
	// storage, we persist it for next time.
	if ocspResp.Status == ocsp.Good {
		if ocspResp.NextUpdate.After(cert.NotAfter) {
			// uh oh, this OCSP response expires AFTER the certificate does, that's kinda bogus.
			// it was the reason a lot of Symantec-validated sites (not Caddy) went down
			// in October 2017. https://twitter.com/mattiasgeniar/status/919432824708648961
			return fmt.Errorf("invalid: OCSP response for %v valid after certificate expiration (%s)",
				cert.Names, cert.NotAfter.Sub(ocspResp.NextUpdate))
		}
		cert.Certificate.OCSPStaple = ocspBytes
		cert.OCSP = ocspResp
		if gotNewOCSP {
			err := certCache.storage.Store(ocspStapleKey, ocspBytes)
			if err != nil {
				return fmt.Errorf("unable to write OCSP staple file for %v: %v", cert.Names, err)
			}
		}
	}

	return nil
}

// getOCSPForCert takes a PEM encoded cert or cert bundle returning the raw OCSP response,
// the parsed response, and an error, if any. The returned []byte can be passed directly
// into the OCSPStaple property of a tls.Certificate. If the bundle only contains the
// issued certificate, this function will try to get the issuer certificate from the
// IssuingCertificateURL in the certificate. If the []byte and/or ocsp.Response return
// values are nil, the OCSP status may be assumed OCSPUnknown.
//
// Borrowed from github.com/xenolf/lego
func getOCSPForCert(bundle []byte) ([]byte, *ocsp.Response, error) {
	// TODO: Perhaps this should be synchronized too, with a Locker?

	certificates, err := parseCertsFromPEMBundle(bundle)
	if err != nil {
		return nil, nil, err
	}

	// We expect the certificate slice to be ordered downwards the chain.
	// SRV CRT -> CA. We need to pull the leaf and issuer certs out of it,
	// which should always be the first two certificates. If there's no
	// OCSP server listed in the leaf cert, there's nothing to do. And if
	// we have only one certificate so far, we need to get the issuer cert.
	issuedCert := certificates[0]
	if len(issuedCert.OCSPServer) == 0 {
		return nil, nil, fmt.Errorf("no OCSP server specified in certificate")
	}
	if len(certificates) == 1 {
		if len(issuedCert.IssuingCertificateURL) == 0 {
			return nil, nil, fmt.Errorf("no URL to issuing certificate")
		}

		resp, err := http.Get(issuedCert.IssuingCertificateURL[0])
		if err != nil {
			return nil, nil, fmt.Errorf("getting issuer certificate: %v", err)
		}
		defer resp.Body.Close()

		issuerBytes, err := ioutil.ReadAll(io.LimitReader(resp.Body, 1024*1024))
		if err != nil {
			return nil, nil, fmt.Errorf("reading issuer certificate: %v", err)
		}

		issuerCert, err := x509.ParseCertificate(issuerBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("parsing issuer certificate: %v", err)
		}

		// insert it into the slice on position 0;
		// we want it ordered right SRV CRT -> CA
		certificates = append(certificates, issuerCert)
	}

	issuerCert := certificates[1]

	ocspReq, err := ocsp.CreateRequest(issuedCert, issuerCert, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("creating OCSP request: %v", err)
	}

	reader := bytes.NewReader(ocspReq)
	req, err := http.Post(issuedCert.OCSPServer[0], "application/ocsp-request", reader)
	if err != nil {
		return nil, nil, fmt.Errorf("making OCSP request: %v", err)
	}
	defer req.Body.Close()

	ocspResBytes, err := ioutil.ReadAll(io.LimitReader(req.Body, 1024*1024))
	if err != nil {
		return nil, nil, fmt.Errorf("reading OCSP response: %v", err)
	}

	ocspRes, err := ocsp.ParseResponse(ocspResBytes, issuerCert)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing OCSP response: %v", err)
	}

	return ocspResBytes, ocspRes, nil
}

// freshOCSP returns true if resp is still fresh,
// meaning that it is not expedient to get an
// updated response from the OCSP server.
func freshOCSP(resp *ocsp.Response) bool {
	nextUpdate := resp.NextUpdate
	// If there is an OCSP responder certificate, and it expires before the
	// OCSP response, use its expiration date as the end of the OCSP
	// response's validity period.
	if resp.Certificate != nil && resp.Certificate.NotAfter.Before(nextUpdate) {
		nextUpdate = resp.Certificate.NotAfter
	}
	// start checking OCSP staple about halfway through validity period for good measure
	refreshTime := resp.ThisUpdate.Add(nextUpdate.Sub(resp.ThisUpdate) / 2)
	return time.Now().Before(refreshTime)
}
