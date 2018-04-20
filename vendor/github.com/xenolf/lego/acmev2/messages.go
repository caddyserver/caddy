package acme

import (
	"time"
)

// RegistrationResource represents all important informations about a registration
// of which the client needs to keep track itself.
type RegistrationResource struct {
	Body accountMessage `json:"body,omitempty"`
	URI  string         `json:"uri,omitempty"`
}

type directory struct {
	NewNonceURL   string `json:"newNonce"`
	NewAccountURL string `json:"newAccount"`
	NewOrderURL   string `json:"newOrder"`
	RevokeCertURL string `json:"revokeCert"`
	KeyChangeURL  string `json:"keyChange"`
	Meta          struct {
		TermsOfService          string   `json:"termsOfService"`
		Website                 string   `json:"website"`
		CaaIdentities           []string `json:"caaIdentities"`
		ExternalAccountRequired bool     `json:"externalAccountRequired"`
	} `json:"meta"`
}

type accountMessage struct {
	Status               string   `json:"status,omitempty"`
	Contact              []string `json:"contact,omitempty"`
	TermsOfServiceAgreed bool     `json:"termsOfServiceAgreed,omitempty"`
	Orders               string   `json:"orders,omitempty"`
	OnlyReturnExisting   bool     `json:"onlyReturnExisting,omitempty"`
}

type orderResource struct {
	URL          string   `json:"url,omitempty"`
	Domains      []string `json:"domains,omitempty"`
	orderMessage `json:"body,omitempty"`
}

type orderMessage struct {
	Status         string       `json:"status,omitempty"`
	Expires        string       `json:"expires,omitempty"`
	Identifiers    []identifier `json:"identifiers"`
	NotBefore      string       `json:"notBefore,omitempty"`
	NotAfter       string       `json:"notAfter,omitempty"`
	Authorizations []string     `json:"authorizations,omitempty"`
	Finalize       string       `json:"finalize,omitempty"`
	Certificate    string       `json:"certificate,omitempty"`
}

type authorization struct {
	Status     string      `json:"status"`
	Expires    time.Time   `json:"expires"`
	Identifier identifier  `json:"identifier"`
	Challenges []challenge `json:"challenges"`
}

type identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type challenge struct {
	URL              string      `json:"url"`
	Type             string      `json:"type"`
	Status           string      `json:"status"`
	Token            string      `json:"token"`
	Validated        time.Time   `json:"validated"`
	KeyAuthorization string      `json:"keyAuthorization"`
	Error            RemoteError `json:"error"`
}

type csrMessage struct {
	Csr string `json:"csr"`
}

type emptyObjectMessage struct {
}

type revokeCertMessage struct {
	Certificate string `json:"certificate"`
}

type deactivateAuthMessage struct {
	Status string `jsom:"status"`
}

// CertificateResource represents a CA issued certificate.
// PrivateKey, Certificate and IssuerCertificate are all
// already PEM encoded and can be directly written to disk.
// Certificate may be a certificate bundle, depending on the
// options supplied to create it.
type CertificateResource struct {
	Domain            string `json:"domain"`
	CertURL           string `json:"certUrl"`
	CertStableURL     string `json:"certStableUrl"`
	AccountRef        string `json:"accountRef,omitempty"`
	PrivateKey        []byte `json:"-"`
	Certificate       []byte `json:"-"`
	IssuerCertificate []byte `json:"-"`
	CSR               []byte `json:"-"`
}
