package caddytls

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
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

// Used for non-200 responses
type httpResponseError struct {
	statusCode int
}

func (e *httpResponseError) Error() string {
	return fmt.Sprintf("HTTP error: %d", e.StatusCode)
}

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
		return nil, &httpResponseError{response.StatusCode}
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
// logs, and returns a list of SCTs (byte slices) or an error.
func getSCTSForCertificateChain(certChain [][]byte, logs []ctLog) ([][]byte, error) {
	sctBytes := make([][]byte, 0)
	addReq := addChainRequest{}
	for _, cert := range certChain {
		addReq.Chain = append(addReq.Chain, base64.StdEncoding.EncodeToString(cert))
	}
	payload, err := json.Marshal(addReq)
	if err != nil {
		return nil, err
	}

	// Chrome CT policy requires at least 1 Google log and 1 non-Google log
	needGoogle := true
	needNonGoogle := true

	// TODO: submit to all these concurrently
	for _, ctLog := range logs {
		// Skip logs that don't contribute to our needs.
		if (ctLog.isGoogle && !needGoogle) || (!ctLog.isGoogle && !needNonGoogle) {
			continue
		}
		sct, err := submitSCT(ctLog.url, payload)
		// TODO: ignore HTTP 4xx errors, which generally indicate "this log
		// isn't accepting new submissions" (we still want to submit in case
		// they have a previous SCT for us) or "this log doesn't acecpt certs
		// from this root"
		if err != nil {
			if err := err.(*httpResponseError); err.statusCode >= 400 && err.statusCode < 500 {
				continue
			}
			log.Printf("[WARNING] Error submitting to CT log: %v", err)
			continue
		}
		bytes, err := sct.AsRawBytes()
		if err != nil {
			return nil, err
		}
		sctBytes = append(sctBytes, bytes)
		if ctLog.isGoogle {
			needGoogle = false
		} else {
			needNonGoogle = false
		}
		if !needGoogle && !needNonGoogle {
			break
		}
	}
	return sctBytes, nil
}

type ctLog struct {
	url string
	// Chrome's CT policy requires one SCT from a Google log, and one SCT from
	// a non-Google log, so we track whether a log is Google or not.
	isGoogle bool
}

type logList struct {
	Logs []struct {
		Description    string `json:"description"`
		URL            string `json:"url"`
		OperatedBy     []int  `json:"operated_by"`
		DisqualifiedAt *int   `json:"disqualified_at"`
	} `json:"logs"`
	Operators []struct {
		Name string `json:"name"`
		ID   int    `json:"id"`
	} `json:"operators"`
}

// GetTrustedCTLogs returns a list of CT logs trusted by Chrome. As the
// browser/CT ecosystem evolves it may return other CT logs as well.
func getTrustedCTLogs() ([]ctLog, error) {
	response, err := httpClient.Get("https://www.gstatic.com/ct/log_list/log_list.json")
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
	for _, operator := range list.Operators {
		if operator.Name == "Google" {
			googleOperator = operator.ID
			break
		}
	}
	logs := make([]ctLog, 0, len(list.Logs))
	for _, log := range list.Logs {
		if log.DisqualifiedAt != nil {
			continue
		}
		logs = append(logs, ctLog{
			url:      log.URL,
			isGoogle: intSliceContains(log.OperatedBy, googleOperator),
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
