package acme

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

const (
	tosAgreementError = "Must agree to subscriber agreement before any further actions"
	invalidNonceError = "JWS has invalid anti-replay nonce"
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

type challengeError struct {
	RemoteError
	records []validationRecord
}

func (c challengeError) Error() string {

	var errStr string
	for _, validation := range c.records {
		errStr = errStr + fmt.Sprintf("\tValidation for %s:%s\n\tResolved to:\n\t\t%s\n\tUsed: %s\n\n",
			validation.Hostname, validation.Port, strings.Join(validation.ResolvedAddresses, "\n\t\t"), validation.UsedAddress)
	}

	return fmt.Sprintf("%s\nError Detail:\n%s", c.RemoteError.Error(), errStr)
}

func handleHTTPError(resp *http.Response) error {
	var errorDetail RemoteError

	contentType := resp.Header.Get("Content-Type")
	if contentType == "application/json" || contentType == "application/problem+json" {
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

	if errorDetail.StatusCode == http.StatusBadRequest && strings.HasPrefix(errorDetail.Detail, invalidNonceError) {
		return NonceError{errorDetail}
	}

	return errorDetail
}

func handleChallengeError(chlng challenge) error {
	return challengeError{chlng.Error, chlng.ValidationRecords}
}
