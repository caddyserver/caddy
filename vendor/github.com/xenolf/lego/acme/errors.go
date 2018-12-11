package acme

import (
	"fmt"
)

// Errors types
const (
	errNS       = "urn:ietf:params:acme:error:"
	BadNonceErr = errNS + "badNonce"
)

// ProblemDetails the problem details object
// - https://tools.ietf.org/html/rfc7807#section-3.1
// - https://tools.ietf.org/html/draft-ietf-acme-acme-16#section-7.3.3
type ProblemDetails struct {
	Type        string       `json:"type,omitempty"`
	Detail      string       `json:"detail,omitempty"`
	HTTPStatus  int          `json:"status,omitempty"`
	Instance    string       `json:"instance,omitempty"`
	SubProblems []SubProblem `json:"subproblems,omitempty"`

	// additional values to have a better error message (Not defined by the RFC)
	Method string `json:"method,omitempty"`
	URL    string `json:"url,omitempty"`
}

// SubProblem a "subproblems"
// - https://tools.ietf.org/html/draft-ietf-acme-acme-16#section-6.7.1
type SubProblem struct {
	Type       string     `json:"type,omitempty"`
	Detail     string     `json:"detail,omitempty"`
	Identifier Identifier `json:"identifier,omitempty"`
}

func (p ProblemDetails) Error() string {
	msg := fmt.Sprintf("acme: error: %d", p.HTTPStatus)
	if len(p.Method) != 0 || len(p.URL) != 0 {
		msg += fmt.Sprintf(" :: %s :: %s", p.Method, p.URL)
	}
	msg += fmt.Sprintf(" :: %s :: %s", p.Type, p.Detail)

	for _, sub := range p.SubProblems {
		msg += fmt.Sprintf(", problem: %q :: %s", sub.Type, sub.Detail)
	}

	if len(p.Instance) == 0 {
		msg += ", url: " + p.Instance
	}

	return msg
}

// NonceError represents the error which is returned
// if the nonce sent by the client was not accepted by the server.
type NonceError struct {
	*ProblemDetails
}
