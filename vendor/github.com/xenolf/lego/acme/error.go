package acme

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

const (
	tosAgreementError = "Must agree to subscriber agreement before any further actions"
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
	decoder := json.NewDecoder(resp.Body)
	err := decoder.Decode(&errorDetail)
	if err != nil {
		return err
	}

	errorDetail.StatusCode = resp.StatusCode

	// Check for errors we handle specifically
	if errorDetail.StatusCode == http.StatusForbidden && errorDetail.Detail == tosAgreementError {
		return TOSError{errorDetail}
	}

	return errorDetail
}

func handleChallengeError(chlng challenge) error {
	return challengeError{chlng.Error, chlng.ValidationRecords}
}
