package acme

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

const (
	tosAgreementError = "Terms of service have changed"
	invalidNonceError = "urn:ietf:params:acme:error:badNonce"
)

// RemoteError is the base type for all errors specific to the ACME protocol.
type RemoteError struct {
	StatusCode int    `json:"status,omitempty"`
	Type       string `json:"type"`
	Detail     string `json:"detail"`
}

func (e RemoteError) Error() string {
	return fmt.Sprintf("acme: Error %d - %s - %s", e.StatusCode, e.Type, e.Detail)
}

// TOSError represents the error which is returned if the user needs to
// accept the TOS.
// TODO: include the new TOS url if we can somehow obtain it.
type TOSError struct {
	RemoteError
}

// NonceError represents the error which is returned if the
// nonce sent by the client was not accepted by the server.
type NonceError struct {
	RemoteError
}

type domainError struct {
	Domain string
	Error  error
}

// ObtainError is returned when there are specific errors available
// per domain. For example in ObtainCertificate
type ObtainError map[string]error

func (e ObtainError) Error() string {
	buffer := bytes.NewBufferString("acme: Error -> One or more domains had a problem:\n")
	for dom, err := range e {
		buffer.WriteString(fmt.Sprintf("[%s] %s\n", dom, err))
	}
	return buffer.String()
}

func handleHTTPError(resp *http.Response) error {
	var errorDetail RemoteError

	contentType := resp.Header.Get("Content-Type")
	if contentType == "application/json" || strings.HasPrefix(contentType, "application/problem+json") {
		err := json.NewDecoder(resp.Body).Decode(&errorDetail)
		if err != nil {
			return err
		}
	} else {
		detailBytes, err := ioutil.ReadAll(limitReader(resp.Body, maxBodySize))
		if err != nil {
			return err
		}
		errorDetail.Detail = string(detailBytes)
	}

	errorDetail.StatusCode = resp.StatusCode

	// Check for errors we handle specifically
	if errorDetail.StatusCode == http.StatusForbidden && errorDetail.Detail == tosAgreementError {
		return TOSError{errorDetail}
	}

	if errorDetail.StatusCode == http.StatusBadRequest && errorDetail.Type == invalidNonceError {
		return NonceError{errorDetail}
	}

	return errorDetail
}

func handleChallengeError(chlng challenge) error {
	return chlng.Error
}
