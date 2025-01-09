package main

import (
	"crypto/sha256"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"strconv"
)

func populateEnvFromClientCert(req *http.Request) {
	if req.TLS == nil || len(req.TLS.VerifiedChains) == 0 {
		fmt.Println("No client certificate provided")
		return
	}

	// Extract the client certificate
	clientCert := req.TLS.VerifiedChains[0][0]

	// Populate environment variables
	os.Setenv("SSL_CLIENT_CERT", string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: clientCert.Raw,
	})))
	os.Setenv("SSL_CLIENT_SUBJECT", clientCert.Subject.String())
	os.Setenv("SSL_CLIENT_ISSUER", clientCert.Issuer.String())
	os.Setenv("SSL_CLIENT_SERIAL", clientCert.SerialNumber.String())

	// SANs (Subject Alternative Names)
	for i, dns := range clientCert.DNSNames {
		os.Setenv("SSL_CLIENT_SAN_DNS_"+strconv.Itoa(i), dns)
	}
	for i, email := range clientCert.EmailAddresses {
		os.Setenv("SSL_CLIENT_SAN_EMAIL_"+strconv.Itoa(i), email)
	}
	for i, ip := range clientCert.IPAddresses {
		os.Setenv("SSL_CLIENT_SAN_IP_"+strconv.Itoa(i), ip.String())
	}
	for i, uri := range clientCert.URIs {
		os.Setenv("SSL_CLIENT_SAN_URI_"+strconv.Itoa(i), uri.String())
	}

	// Example: Fingerprint
	fingerprint := sha256.Sum256(clientCert.Raw)
	os.Setenv("SSL_CLIENT_FINGERPRINT", fmt.Sprintf("%x", fingerprint))
}

func handler(w http.ResponseWriter, r *http.Request) {
	// Populate environment variables
	populateEnvFromClientCert(r)

	// Respond with the environment variables for testing
	fmt.Fprintf(w, "SSL_CLIENT_CERT: %s\n", os.Getenv("SSL_CLIENT_CERT"))
	fmt.Fprintf(w, "SSL_CLIENT_SUBJECT: %s\n", os.Getenv("SSL_CLIENT_SUBJECT"))
	fmt.Fprintf(w, "SSL_CLIENT_ISSUER: %s\n", os.Getenv("SSL_CLIENT_ISSUER"))
	fmt.Fprintf(w, "SSL_CLIENT_SERIAL: %s\n", os.Getenv("SSL_CLIENT_SERIAL"))
	fmt.Fprintf(w, "SSL_CLIENT_FINGERPRINT: %s\n", os.Getenv("SSL_CLIENT_FINGERPRINT"))
}
