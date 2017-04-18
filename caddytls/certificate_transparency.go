package caddytls

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// This code borrows heavily from https://github.com/grahamedgecombe/ct-submit

type addChainRequest struct {
	Chain []string `json:"chain"`
}

type signedCertificateTimestamp struct {
	Version    uint8  `json:"sct_version"`
	LogID      string `json:"id"`
	Timestamp  int64  `json:"timestamp"`
	Extensions string `json:"extensions"`
	Signature  string `json:"signature"`
}

// AsRawBytes converts the SCT from the JSON form that the submission API
// returns into the raw binary form that the TLS handshake expects.
func (sct *signedCertificateTimestamp) AsRawBytes() ([]byte, error) {
	b := new(bytes.Buffer)
	// Version
	binary.Write(b, binary.BigEndian, sct.Version)

	// LogID
	logBytes, err := base64.StdEncoding.DecodeString(sct.LogID)
	if err != nil {
		return nil, err
	}
	b.Write(logBytes)

	// Timestamp
	binary.Write(b, binary.BigEndian, sct.Timestamp)

	// Extensions
	extensionBytes, err := base64.StdEncoding.DecodeString(sct.Extensions)
	if err != nil {
		return nil, err
	}
	if len(extensionBytes) > 65535 {
		return nil, fmt.Errorf("Extensions is too long: %d bytes", len(extensionBytes))
	}
	binary.Write(b, binary.BigEndian, uint16(len(extensionBytes)))
	b.Write(extensionBytes)

	// Signature
	signatureBytes, err := base64.StdEncoding.DecodeString(sct.Signature)
	if err != nil {
		return nil, err
	}
	b.Write(signatureBytes)

	return b.Bytes(), nil
}

// Makes an HTTP request to the log server and returns the parsed SCT response.
// If the cert is already in the log, the log will simply return the previously
// generated SCT, making this idempotent.
func submitSCT(client http.Client, url string, payload []byte) (*signedCertificateTimestamp, error) {
	if !strings.Contains(url, "://") {
		// Allow people to omit the protocol and default to HTTPS.
		url = "https://" + url
	}
	if !strings.HasSuffix(url, "/") {
		url = url + "/"
	}

	response, err := client.Post(url+"ct/v1/add-chain", "application/json", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP error %d", response.StatusCode)
	}
	sct := &signedCertificateTimestamp{}
	err = json.NewDecoder(response.Body).Decode(&sct)
	if err != nil {
		return nil, err
	}
	return sct, nil
}

// GetSCTSForCertificateChain takes a certificate chain, and a list of target
// log URLs, and returns a list of SCTs (byte slices) or an error.

// TODO: support submitting to multiple logs and just getting as many SCTs as
// we can, even if some logs error.
func GetSCTSForCertificateChain(certChain [][]byte, logURLs []string) ([][]byte, error) {
	sctBytes := make([][]byte, 0)
	addReq := addChainRequest{}
	for _, cert := range certChain {
		addReq.Chain = append(addReq.Chain, base64.StdEncoding.EncodeToString(cert))
	}
	payload, err := json.Marshal(addReq)
	if err != nil {
		return nil, err
	}

	httpClient := http.Client{Timeout: 30 * time.Second}
	for _, url := range logURLs {
		sct, err := submitSCT(httpClient, url, payload)
		if err != nil {
			return nil, err
		}
		bytes, err := sct.AsRawBytes()
		if err != nil {
			return nil, err
		}
		sctBytes = append(sctBytes, bytes)
	}
	return sctBytes, nil
}
