package caddytls

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"strings"
	"sync"
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
	return fmt.Sprintf("HTTP error: %d", e.statusCode)
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

// getSCTSForCertificateChain takes a certificate chain, and a list of target
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

	type result struct {
		log ctLog
		sct *signedCertificateTimestamp
		err error
	}
	var wg sync.WaitGroup
	// Buffered chan so that the goroutines can just exit once they've got a
	// result.
	results := make(chan result, len(logs))
	var submit = func(log ctLog) {
		defer wg.Done()
		sct, err := submitSCT(log.url, payload)
		results <- result{log, sct, err}
	}
	wg.Add(len(logs))
	for _, ctLog := range logs {
		go submit(ctLog)
	}
	wg.Wait()
	close(results)

	// Chrome CT policy requires at least 1 Google log and 1 non-Google log
	needGoogle := true
	needNonGoogle := true
	for result := range results {
		if result.err != nil {
			// Ignore HTTP 4xx errors, which generally indicate "this log isn't
			// accepting new submissions" (we still want to submit in case they
			// have a previous SCT for us) or "this log doesn't acecpt certs
			// from this root"
			if err, ok := result.err.(*httpResponseError); ok {
				if err.statusCode >= 400 && err.statusCode < 500 {
					continue
				}
			}
			log.Printf("[WARNING] Error submitting to CT log: %v", result.err)
			continue
		}
		// Skip logs that don't contribute to our needs.
		if (result.log.isGoogle && !needGoogle) || (!result.log.isGoogle && !needNonGoogle) {
			continue
		}
		bytes, err := result.sct.AsRawBytes()
		if err != nil {
			log.Printf("[WARNING] Got SCT which couldn't be converted to bytes: %v", err)
			continue
		}
		sctBytes = append(sctBytes, bytes)
		if result.log.isGoogle {
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

// getTrustedCTLogs returns a list of CT logs trusted by Chrome. As the
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
	// Shuffle the order of the logs so that across many consumers, we spread
	// the load out between different logs.
	shuffleLogs(logs)
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

func shuffleLogs(logs []ctLog) {
	for i := 1; i < len(logs); i++ {
		j := rand.Intn(i)
		logs[i], logs[j] = logs[j], logs[i]
	}
}

// Check whether two lists of CT logs contain the same logs (ignoring order).
func logListsEqual(a []ctLog, b []ctLog) bool {
	if len(a) != len(b) {
		return false
	}
	set := make(map[string]struct{})
	// Make a set of the URLs in the first slice
	for _, log := range a {
		set[log.url] = struct{}{}
	}
	// If anything from the second slice isn't in the set, they're not equally.
	for _, log := range b {
		if _, ok := set[log.url]; !ok {
			return false
		}
	}
	// If everything from second slice was in the first, and they're the same
	// length, the slices are equal.
	return true
}

// This is the OID for the embedded SCT X.509 extension (see the RFC 6962)
var x509SCTOid = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
var ocspSCTOid = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 5}

func hasExtension(extensions []pkix.Extension, needle asn1.ObjectIdentifier) bool {
	for _, ext := range extensions {
		if ext.Id.Equal(needle) {
			return true
		}
	}
	return false
}

// Checks whether or not a certificate also requires external SCTs (because it
// doesn't have any embedded SCTs and neither does its OCSP response)
func certificateNeedsSCTs(cert *Certificate, leaf *x509.Certificate) bool {
	return !hasExtension(leaf.Extensions, x509SCTOid) &&
		!(cert.OCSP != nil && hasExtension(cert.OCSP.Extensions, ocspSCTOid))
}
