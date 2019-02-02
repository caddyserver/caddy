// Package acme contains all objects related the ACME endpoints.
// https://tools.ietf.org/html/draft-ietf-acme-acme-16
package acme

import (
	"encoding/json"
	"time"
)

// Challenge statuses
// https://tools.ietf.org/html/draft-ietf-acme-acme-16#section-7.1.6
const (
	StatusPending     = "pending"
	StatusInvalid     = "invalid"
	StatusValid       = "valid"
	StatusProcessing  = "processing"
	StatusDeactivated = "deactivated"
	StatusExpired     = "expired"
	StatusRevoked     = "revoked"
)

// Directory the ACME directory object.
// - https://tools.ietf.org/html/draft-ietf-acme-acme-16#section-7.1.1
type Directory struct {
	NewNonceURL   string `json:"newNonce"`
	NewAccountURL string `json:"newAccount"`
	NewOrderURL   string `json:"newOrder"`
	NewAuthzURL   string `json:"newAuthz"`
	RevokeCertURL string `json:"revokeCert"`
	KeyChangeURL  string `json:"keyChange"`
	Meta          Meta   `json:"meta"`
}

// Meta the ACME meta object (related to Directory).
// - https://tools.ietf.org/html/draft-ietf-acme-acme-16#section-7.1.1
type Meta struct {
	// termsOfService (optional, string):
	// A URL identifying the current terms of service.
	TermsOfService string `json:"termsOfService"`

	// website (optional, string):
	// An HTTP or HTTPS URL locating a website providing more information about the ACME server.
	Website string `json:"website"`

	// caaIdentities (optional, array of string):
	// The hostnames that the ACME server recognizes as referring to itself
	// for the purposes of CAA record validation as defined in [RFC6844].
	// Each string MUST represent the same sequence of ASCII code points
	// that the server will expect to see as the "Issuer Domain Name" in a CAA issue or issuewild property tag.
	// This allows clients to determine the correct issuer domain name to use when configuring CAA records.
	CaaIdentities []string `json:"caaIdentities"`

	// externalAccountRequired (optional, boolean):
	// If this field is present and set to "true",
	// then the CA requires that all new- account requests include an "externalAccountBinding" field
	// associating the new account with an external account.
	ExternalAccountRequired bool `json:"externalAccountRequired"`
}

// ExtendedAccount a extended Account.
type ExtendedAccount struct {
	Account
	// Contains the value of the response header `Location`
	Location string `json:"-"`
}

// Account the ACME account Object.
// - https://tools.ietf.org/html/draft-ietf-acme-acme-16#section-7.1.2
// - https://tools.ietf.org/html/draft-ietf-acme-acme-16#section-7.3
type Account struct {
	// status (required, string):
	// The status of this account.
	// Possible values are: "valid", "deactivated", and "revoked".
	// The value "deactivated" should be used to indicate client-initiated deactivation
	// whereas "revoked" should be used to indicate server- initiated deactivation. (See Section 7.1.6)
	Status string `json:"status,omitempty"`

	// contact (optional, array of string):
	// An array of URLs that the server can use to contact the client for issues related to this account.
	// For example, the server may wish to notify the client about server-initiated revocation or certificate expiration.
	// For information on supported URL schemes, see Section 7.3
	Contact []string `json:"contact,omitempty"`

	// termsOfServiceAgreed (optional, boolean):
	// Including this field in a new-account request,
	// with a value of true, indicates the client's agreement with the terms of service.
	// This field is not updateable by the client.
	TermsOfServiceAgreed bool `json:"termsOfServiceAgreed,omitempty"`

	// orders (required, string):
	// A URL from which a list of orders submitted by this account can be fetched via a POST-as-GET request,
	// as described in Section 7.1.2.1.
	Orders string `json:"orders,omitempty"`

	// onlyReturnExisting (optional, boolean):
	// If this field is present with the value "true",
	// then the server MUST NOT create a new account if one does not already exist.
	// This allows a client to look up an account URL based on an account key (see Section 7.3.1).
	OnlyReturnExisting bool `json:"onlyReturnExisting,omitempty"`

	// externalAccountBinding (optional, object):
	// An optional field for binding the new account with an existing non-ACME account (see Section 7.3.4).
	ExternalAccountBinding json.RawMessage `json:"externalAccountBinding,omitempty"`
}

// ExtendedOrder a extended Order.
type ExtendedOrder struct {
	Order
	// The order URL, contains the value of the response header `Location`
	Location string `json:"-"`
}

// Order the ACME order Object.
// - https://tools.ietf.org/html/draft-ietf-acme-acme-16#section-7.1.3
type Order struct {
	// status (required, string):
	// The status of this order.
	// Possible values are: "pending", "ready", "processing", "valid", and "invalid".
	Status string `json:"status,omitempty"`

	// expires (optional, string):
	// The timestamp after which the server will consider this order invalid,
	// encoded in the format specified in RFC 3339 [RFC3339].
	// This field is REQUIRED for objects with "pending" or "valid" in the status field.
	Expires string `json:"expires,omitempty"`

	// identifiers (required, array of object):
	// An array of identifier objects that the order pertains to.
	Identifiers []Identifier `json:"identifiers"`

	// notBefore (optional, string):
	// The requested value of the notBefore field in the certificate,
	// in the date format defined in [RFC3339].
	NotBefore string `json:"notBefore,omitempty"`

	// notAfter (optional, string):
	// The requested value of the notAfter field in the certificate,
	// in the date format defined in [RFC3339].
	NotAfter string `json:"notAfter,omitempty"`

	// error (optional, object):
	// The error that occurred while processing the order, if any.
	// This field is structured as a problem document [RFC7807].
	Error *ProblemDetails `json:"error,omitempty"`

	// authorizations (required, array of string):
	// For pending orders,
	// the authorizations that the client needs to complete before the requested certificate can be issued (see Section 7.5),
	// including unexpired authorizations that the client has completed in the past for identifiers specified in the order.
	// The authorizations required are dictated by server policy
	// and there may not be a 1:1 relationship between the order identifiers and the authorizations required.
	// For final orders (in the "valid" or "invalid" state), the authorizations that were completed.
	// Each entry is a URL from which an authorization can be fetched with a POST-as-GET request.
	Authorizations []string `json:"authorizations,omitempty"`

	// finalize (required, string):
	// A URL that a CSR must be POSTed to once all of the order's authorizations are satisfied to finalize the order.
	// The result of a successful finalization will be the population of the certificate URL for the order.
	Finalize string `json:"finalize,omitempty"`

	// certificate (optional, string):
	// A URL for the certificate that has been issued in response to this order
	Certificate string `json:"certificate,omitempty"`
}

// Authorization the ACME authorization object.
// - https://tools.ietf.org/html/draft-ietf-acme-acme-16#section-7.1.4
type Authorization struct {
	// status (required, string):
	// The status of this authorization.
	// Possible values are: "pending", "valid", "invalid", "deactivated", "expired", and "revoked".
	Status string `json:"status"`

	// expires (optional, string):
	// The timestamp after which the server will consider this authorization invalid,
	// encoded in the format specified in RFC 3339 [RFC3339].
	// This field is REQUIRED for objects with "valid" in the "status" field.
	Expires time.Time `json:"expires,omitempty"`

	// identifier (required, object):
	// The identifier that the account is authorized to represent
	Identifier Identifier `json:"identifier,omitempty"`

	// challenges (required, array of objects):
	// For pending authorizations, the challenges that the client can fulfill in order to prove possession of the identifier.
	// For valid authorizations, the challenge that was validated.
	// For invalid authorizations, the challenge that was attempted and failed.
	// Each array entry is an object with parameters required to validate the challenge.
	// A client should attempt to fulfill one of these challenges,
	// and a server should consider any one of the challenges sufficient to make the authorization valid.
	Challenges []Challenge `json:"challenges,omitempty"`

	// wildcard (optional, boolean):
	// For authorizations created as a result of a newOrder request containing a DNS identifier
	// with a value that contained a wildcard prefix this field MUST be present, and true.
	Wildcard bool `json:"wildcard,omitempty"`
}

// ExtendedChallenge a extended Challenge.
type ExtendedChallenge struct {
	Challenge
	// Contains the value of the response header `Retry-After`
	RetryAfter string `json:"-"`
	// Contains the value of the response header `Link` rel="up"
	AuthorizationURL string `json:"-"`
}

// Challenge the ACME challenge object.
// - https://tools.ietf.org/html/draft-ietf-acme-acme-16#section-7.1.5
// - https://tools.ietf.org/html/draft-ietf-acme-acme-16#section-8
type Challenge struct {
	// type (required, string):
	// The type of challenge encoded in the object.
	Type string `json:"type"`

	// url (required, string):
	// The URL to which a response can be posted.
	URL string `json:"url"`

	// status (required, string):
	// The status of this challenge. Possible values are: "pending", "processing", "valid", and "invalid".
	Status string `json:"status"`

	// validated (optional, string):
	// The time at which the server validated this challenge,
	// encoded in the format specified in RFC 3339 [RFC3339].
	// This field is REQUIRED if the "status" field is "valid".
	Validated time.Time `json:"validated,omitempty"`

	// error (optional, object):
	// Error that occurred while the server was validating the challenge, if any,
	// structured as a problem document [RFC7807].
	// Multiple errors can be indicated by using subproblems Section 6.7.1.
	// A challenge object with an error MUST have status equal to "invalid".
	Error *ProblemDetails `json:"error,omitempty"`

	// token (required, string):
	// A random value that uniquely identifies the challenge.
	// This value MUST have at least 128 bits of entropy.
	// It MUST NOT contain any characters outside the base64url alphabet,
	// and MUST NOT include base64 padding characters ("=").
	// See [RFC4086] for additional information on randomness requirements.
	// https://tools.ietf.org/html/draft-ietf-acme-acme-16#section-8.3
	// https://tools.ietf.org/html/draft-ietf-acme-acme-16#section-8.4
	Token string `json:"token"`

	// https://tools.ietf.org/html/draft-ietf-acme-acme-16#section-8.1
	KeyAuthorization string `json:"keyAuthorization"`
}

// Identifier the ACME identifier object.
// - https://tools.ietf.org/html/draft-ietf-acme-acme-16#section-9.7.7
type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// CSRMessage Certificate Signing Request
// - https://tools.ietf.org/html/draft-ietf-acme-acme-16#section-7.4
type CSRMessage struct {
	// csr (required, string):
	// A CSR encoding the parameters for the certificate being requested [RFC2986].
	// The CSR is sent in the base64url-encoded version of the DER format.
	// (Note: Because this field uses base64url, and does not include headers, it is different from PEM.).
	Csr string `json:"csr"`
}

// RevokeCertMessage a certificate revocation message
// - https://tools.ietf.org/html/draft-ietf-acme-acme-16#section-7.6
// - https://tools.ietf.org/html/rfc5280#section-5.3.1
type RevokeCertMessage struct {
	// certificate (required, string):
	// The certificate to be revoked, in the base64url-encoded version of the DER format.
	// (Note: Because this field uses base64url, and does not include headers, it is different from PEM.)
	Certificate string `json:"certificate"`

	// reason (optional, int):
	// One of the revocation reasonCodes defined in Section 5.3.1 of [RFC5280] to be used when generating OCSP responses and CRLs.
	// If this field is not set the server SHOULD omit the reasonCode CRL entry extension when generating OCSP responses and CRLs.
	// The server MAY disallow a subset of reasonCodes from being used by the user.
	// If a request contains a disallowed reasonCode the server MUST reject it with the error type "urn:ietf:params:acme:error:badRevocationReason".
	// The problem document detail SHOULD indicate which reasonCodes are allowed.
	Reason *uint `json:"reason,omitempty"`
}
