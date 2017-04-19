package caddytls

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
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

var httpClient = http.Client{Timeout: 30 * time.Second}

// Makes an HTTP request to the log server and returns the parsed SCT response.
// If the cert is already in the log, the log will simply return the previously
// generated SCT, making this idempotent.
func submitSCT(url string, payload []byte) (*signedCertificateTimestamp, error) {
	// Protocol must be HTTPS, so require people to omit it.
	url = "https://" + url
	if !strings.HasSuffix(url, "/") {
		url = url + "/"
	}

	response, err := httpClient.Post(url+"ct/v1/add-chain", "application/json", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP error %d", response.StatusCode)
	}
	sct := &signedCertificateTimestamp{}
	// Limit response to 10MB, there's no reason they should ever be that
	// large, and this guards against malicious or poorly run servers.
	err = json.NewDecoder(io.LimitReader(response.Body, 10*1024*1024)).Decode(&sct)
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

	for _, url := range logURLs {
		sct, err := submitSCT(url, payload)
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

type ctLog struct {
	url string
	// Chrome's CT policy requires one SCT from a Google log, and one SCT from
	// a non-Google log, so we track whether a log is Google or not.
	is_google bool
}

type logList struct {
	logs []struct {
		description string
		url         string
		operated_by []int
	}
	operators []struct {
		name string
		id   int
	}
}

// GetTrustedCTLogs returns a list of CT logs trusted by Chrome. As the
// browser/CT ecosystem evolves it may return other CT logs as well.
func GetTrustedCTLogs() ([]ctLog, error) {
	response, err := http.Get("https://www.gstatic.com/ct/log_list/log_list.json")
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP response error: %d", response.StatusCode)
	}
	list := logList{}
	// Limit the amount we read to 10MB to defend against a DoS. Currently this
	// file is ~2.5KB so this leaves us plenty of breathing room.
	err = json.NewDecoder(io.LimitReader(response.Body, 10*1024*1024)).Decode(&list)
	if err != nil {
		return nil, err
	}

	var googleOperator int
	for _, operator := range list.operators {
		if operator.name == "Google" {
			googleOperator = operator.id
			break
		}
	}
	logs := make([]ctLog, 0, len(list.logs))
	for _, log := range list.logs {
		logs = append(logs, ctLog{
			url:       log.url,
			is_google: intSliceContains(log.operated_by, googleOperator),
		})
	}
	return logs, nil
}

func intSliceContains(data []int, needle int) bool {
	for _, d := range data {
		if d == needle {
			return true
		}
	}
	return false
}
